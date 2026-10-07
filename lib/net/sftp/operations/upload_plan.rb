require 'net/ssh/loggable'

module Net; module SFTP; module Operations

  class Upload
    class Plan
      Operation = Struct.new(:id, :action, :local, :remote, :target, :mode,
        :depth, :depends_on, :condition, :status, :group)

      attr_reader :local, :remote, :operations, :hard_link_groups

      def self.build(local, remote, options={})
        new(local, remote, options).build!
      end

      def initialize(local, remote, options={})
        @local = local
        @remote = remote
        @create_root = options.fetch(:create_root, false)
        @preserve_permissions = options.fetch(:preserve_permissions, true)
        @hard_links = options.fetch(:hard_links, :preserve)
        @operations = []
        @hard_link_groups = Hash.new { |hash, key| hash[key] = [] }
        @directories = {}
      end

      def build!
        root_stat = ::File.lstat(local)
        if root_stat.symlink?
          add_symlink(local, remote, 0, [])
          sort_operations!
          return self
        end

        raise ArgumentError, "expected a directory to upload" unless root_stat.directory?

        parent_id = nil
        if @create_root
          directory = add_directory(local, remote, 0, nil)
          parent_id = directory.id
        else
          add_check(remote, 0, [])
        end

        scan_directory(local, remote, 1, parent_id)
        add_hard_link_operations!
        add_directory_permissions!
        sort_operations!
        self
      end

      def without_hard_links
        replacement = {}
        removed_ids = operations.select do |operation|
          operation.action == :remove && operation.condition && operation.id.end_with?(':hardlink-remove')
        end.map(&:id)
        converted = operations.reject { |operation| removed_ids.include?(operation.id) }.flat_map do |operation|
          next operation unless operation.action == :hardlink

          upload = Operation.new(id_for(:upload, operation.local, operation.remote), :upload,
            operation.local, operation.remote, nil, operation.mode, operation.depth,
            operation.depends_on.select { |dependency| dependency.start_with?('mkdir:') },
            nil, :pending, operation.group)
          converted_operations = [upload]
          if @preserve_permissions
            permissions = permissions_operation(upload)
            converted_operations << permissions
          end
          replacement[operation.id] = converted_operations
        end

        converted.each do |operation|
          operation.depends_on -= removed_ids
          operation.depends_on = Array(operation.depends_on).flat_map do |dependency|
            if replacement.key?(dependency)
              replacement[dependency].map(&:id)
            else
              [dependency]
            end
          end
        end

        clone_with_operations(converted)
      end

      def to_s
        lines = ["upload plan: #{local} -> #{remote}"]
        operations.each { |operation| lines << format_operation(operation) }
        lines.join("\n")
      end

      private

        def clone_with_operations(operations)
          plan = self.class.new(local, remote,
            :create_root => @create_root,
            :preserve_permissions => @preserve_permissions,
            :hard_links => :copy)
          operations.each do |operation|
            copy = Operation.new(*operation.to_a)
            copy.status = :pending
            plan.operations << copy
          end
          plan.send(:sort_operations!)
          plan
        end

        def scan_directory(local_dir, remote_dir, depth, parent_id)
          ::Dir.entries(local_dir).sort.each do |name|
            next if name == "." || name == ".."
            add_entry(::File.join(local_dir, name), ::File.join(remote_dir, name), depth, parent_id)
          end
        end

        def add_entry(lpath, rpath, depth, parent_id)
          stat = ::File.lstat(lpath)
          if stat.directory?
            directory = add_directory(lpath, rpath, depth, parent_id)
            scan_directory(lpath, rpath, depth + 1, directory.id)
          elsif stat.symlink?
            add_symlink(lpath, rpath, depth, parent_id)
          elsif stat.file?
            hard_link_groups[[stat.dev, stat.ino]] << {
              :stat => stat, :local => lpath, :remote => rpath, :mode => stat.mode,
              :depth => depth, :parent_id => parent_id
            }
          else
            raise ArgumentError, "unsupported local entry type for upload: #{lpath.inspect}"
          end
        end

        def add_directory(lpath, rpath, depth, parent_id)
          directory = Operation.new(id_for(:mkdir, lpath, rpath), :mkdir, lpath, rpath, nil,
            nil, depth, Array(parent_id), nil, :pending, nil)
          directories[rpath] = directory
          operations << directory
          directory
        end

        def add_check(rpath, depth, depends_on)
          operations << Operation.new(id_for(:check, nil, rpath), :check, nil, rpath, nil,
            nil, depth, depends_on, nil, :pending, nil)
        end

        def add_symlink(lpath, rpath, depth, parent_id)
          parent_dependencies = Array(parent_id)
          remove = Operation.new("#{rpath}:symlink-remove", :remove, nil, rpath, nil,
            nil, depth, parent_dependencies.dup, :if_same_type_exists, :skipped, nil)
          symlink = Operation.new(id_for(:symlink, lpath, rpath), :symlink, lpath, rpath,
            ::File.readlink(lpath), nil, depth, parent_dependencies + [remove.id], nil, :pending, nil)
          operations.concat([remove, symlink])
        end

        def add_hard_link_operations!
          hard_link_groups.each_value do |entries|
            entries.sort_by! { |entry| entry[:local] }
            source = entries.first
            stat = source[:stat]
            group = source[:group] = "#{stat.dev}:#{stat.ino}"

            upload = upload_operation(source, group, source[:parent_id])
            operations << upload
            terminal = upload
            if @preserve_permissions
              permissions = permissions_operation(upload)
              operations << permissions
              terminal = permissions
            end

            next unless @hard_links == :preserve
            entries[1..].each do |entry|
              entry[:group] = group
              dependencies = Array(entry[:parent_id])
              remove = Operation.new("#{entry[:remote]}:hardlink-remove", :remove, nil,
                entry[:remote], nil, nil, entry[:depth], dependencies.dup,
                :if_same_type_exists, :skipped, group)
              hardlink = Operation.new(id_for(:hardlink, entry[:local], entry[:remote]),
                :hardlink, entry[:local], entry[:remote], source[:remote], entry[:mode] & 0o7777,
                entry[:depth], dependencies + [remove.id, terminal.id], nil, :pending, group)
              operations.concat([remove, hardlink])
            end
          end
        end

        def upload_operation(entry, group, parent_id)
          Operation.new(id_for(:upload, entry[:local], entry[:remote]), :upload,
            entry[:local], entry[:remote], nil, entry[:mode] & 0o7777,
            entry[:depth], Array(parent_id), nil, :pending, group)
        end

        def permissions_operation(source)
          Operation.new("#{source.id}:permissions", :setstat,
            source.local, source.remote, nil, source.mode, source.depth,
            [source.id], nil, :pending, source.group)
        end

        def add_directory_permissions!
          return unless @preserve_permissions

          directories.each_value do |directory|
            stat = ::File.lstat(directory.local)
            dependencies = descendants_of(directory.remote).map(&:id)
            dependencies.delete(directory.id)
            operations << Operation.new("#{directory.id}:permissions", :setstat,
              directory.local, directory.remote, nil, stat.mode & 0o7777,
              directory.depth, dependencies, nil, :pending, nil)
          end
        end

        def descendants_of(rpath)
          prefix = rpath.end_with?(::File::SEPARATOR) ? rpath : "#{rpath}#{::File::SEPARATOR}"
          operations.select do |operation|
            operation.remote && operation.remote != rpath && operation.remote.start_with?(prefix)
          end
        end

        def sort_operations!
          operations.sort_by! do |operation|
            phase = case operation.action
                    when :check then 0
                    when :mkdir then 1
                    when :remove then 2
                    when :upload then 3
                    when :symlink then 4
                    when :hardlink then 5
                    when :setstat then directory_setstat?(operation) ? 7 : 6
                    else 8
                    end
            [phase, operation.depth, operation.remote.to_s]
          end
        end

        def directory_setstat?(operation)
          operation.local && ::File.lstat(operation.local).directory?
        rescue Errno::ENOENT
          false
        end

        def id_for(action, local, remote)
          "#{action}:#{local || remote}"
        end

        def format_operation(operation)
          suffix = case operation.action
                   when :upload then "#{operation.local} -> #{operation.remote}"
                   when :symlink then "#{operation.remote} -> #{operation.target}"
                   when :hardlink then "#{operation.remote} => #{operation.target}"
                   when :setstat then "#{operation.remote} mode #{'%04o' % operation.mode}"
                   else operation.remote.to_s
                   end
          details = format("%-8s %s", operation.action, suffix)
          details << " [if same type exists]" if operation.condition
          if operation.depends_on.any?
            details << " (depends on: #{operation.depends_on.join(', ')})"
          end
          details
        end

        attr_reader :directories
    end
  end

end; end; end
