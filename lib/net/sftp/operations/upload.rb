require 'net/ssh/loggable'
require 'net/sftp/operations/upload_plan'

module Net; module SFTP; module Operations

  # A general purpose uploader module for Net::SFTP. It can upload IO objects,
  # files, and even entire directory trees via SFTP, and provides a flexible
  # progress reporting mechanism.
  #
  # To upload a single file to the remote server, simply specify both the
  # local and remote paths:
  #
  #   uploader = sftp.upload("/path/to/local.txt", "/path/to/remote.txt")
  #
  # By default, this operates asynchronously, so if you want to block until
  # the upload finishes, you can use the 'bang' variant:
  #
  #   sftp.upload!("/path/to/local.txt", "/path/to/remote.txt")
  #
  # Or, if you have multiple uploads that you want to run in parallel, you can
  # employ the #wait method of the returned object:
  #
  #   uploads = %w(file1 file2 file3).map { |f| sftp.upload(f, "remote/#{f}") }
  #   uploads.each { |u| u.wait }
  #
  # To upload an entire directory tree, recursively, simply pass the directory
  # path as the first parameter:
  #
  #   sftp.upload!("/path/to/directory", "/path/to/remote")
  #
  # This will upload "/path/to/directory", its contents, its subdirectories,
  # and their contents, recursively, to "/path/to/remote" on the remote server.
  #
  # For uploading a directory without creating it, do
  # sftp.upload!("/path/to/directory", "/path/to/remote", :mkdir => false)
  #
  # If you want to send data to a file on the remote server, but the data is
  # in memory, you can pass an IO object and upload its contents:
  #
  #   require 'stringio'
  #   io = StringIO.new(data)
  #   sftp.upload!(io, "/path/to/remote")
  #
  # The following options are supported:
  #
  # * <tt>:progress</tt> - either a block or an object to act as a progress
  #   callback. See the discussion of "progress monitoring" below.
  # * <tt>:requests</tt> - the number of pending SFTP requests to allow at
  #   any given time. When uploading an entire directory tree recursively,
  #   this will default to 16, otherwise it will default to 2. Setting this
  #   higher might improve throughput. Reducing it will reduce throughput.
  # * <tt>:read_size</tt> - the maximum number of bytes to read at a time
  #   from the source. Increasing this value might improve throughput. It
  #   defaults to 32,000 bytes.
  # * <tt>:name</tt> - the filename to report to the progress monitor when
  #   an IO object is given as +local+. This defaults to "<memory>".
  # * <tt>:hard_links</tt> - set to <tt>:preserve</tt> (the default) to group
  #   local regular files by lstat device/inode and create hard links on the
  #   server. Set to <tt>:copy</tt> to upload each alias independently.
  # * <tt>:on_unsupported_hard_links</tt> - set to <tt>:raise</tt> (the
  #   default) to fail before execution when SFTP 6 or a negotiated hard-link
  #   extension is unavailable. Set to <tt>:copy</tt> to explicitly degrade to
  #   independent file uploads.
  # * <tt>:preserve_permissions</tt> - defaults to true. Directories are
  #   created with temporary owner-write permissions and their final
  #   permissions are applied after their contents and links are in place.
  #
  # Recursive uploads always lstat local entries. Symbolic links are uploaded
  # as symbolic links with the exact readlink target, including relative or
  # cyclic targets, and are never traversed. Before requests are sent the
  # recursive uploader builds an inspectable dependency plan available from
  # #plan; the plan is also passed as <tt>options[:plan]</tt> when supplied by
  # the caller.
  #
  # == Progress Monitoring
  #
  # Sometimes it is desirable to track the progress of an upload. There are
  # two ways to do this: either using a callback block, or a special custom
  # object.
  #
  # Using a block it's pretty straightforward:
  #
  #   sftp.upload!("local", "remote") do |event, uploader, *args|
  #     case event
  #     when :open then
  #       # args[0] : file metadata
  #       puts "starting upload: #{args[0].local} -> #{args[0].remote} (#{args[0].size} bytes}"
  #     when :put then
  #       # args[0] : file metadata
  #       # args[1] : byte offset in remote file
  #       # args[2] : data being written (as string)
  #       puts "writing #{args[2].length} bytes to #{args[0].remote} starting at #{args[1]}"
  #     when :close then
  #       # args[0] : file metadata
  #       puts "finished with #{args[0].remote}"
  #     when :mkdir then
  #       # args[0] : remote path name
  #       puts "creating directory #{args[0]}"
  #     when :finish then
  #       puts "all done!"
  #   end
  #
  # However, for more complex implementations (e.g., GUI interfaces and such)
  # a block can become cumbersome. In those cases, you can create custom
  # handler objects that respond to certain methods, and then pass your handler
  # to the uploader:
  #
  #   class CustomHandler
  #     def on_open(uploader, file)
  #       puts "starting upload: #{file.local} -> #{file.remote} (#{file.size} bytes)"
  #     end
  #
  #     def on_put(uploader, file, offset, data)
  #       puts "writing #{data.length} bytes to #{file.remote} starting at #{offset}"
  #     end
  #
  #     def on_close(uploader, file)
  #       puts "finished with #{file.remote}"
  #     end
  #
  #     def on_mkdir(uploader, path)
  #       puts "creating directory #{path}"
  #     end
  #
  #     def on_finish(uploader)
  #       puts "all done!"
  #     end
  #   end
  #
  #   sftp.upload!("local", "remote", :progress => CustomHandler.new)
  #
  # If you omit any of those methods, the progress updates for those missing
  # events will be ignored. You can create a catchall method named "call" for
  # those, instead.
  class Upload
    include Net::SSH::Loggable

    # The source of the upload (on the local server)
    attr_reader :local

    # The destination of the upload (on the remote server)
    attr_reader :remote

    # The hash of options that were given when the object was instantiated
    attr_reader :options

    # The SFTP session object used by this upload instance
    attr_reader :sftp

    # The inspectable operation plan for recursive uploads.
    attr_reader :plan

    # The properties hash for this object
    attr_reader :properties

    # Instantiates a new uploader process on top of the given SFTP session.
    # +local+ is either an IO object containing data to upload, or a string
    # identifying a file or directory on the local host. +remote+ is a string
    # identifying the location on the remote host that the upload should
    # target.
    #
    # This will return immediately, and requires that the SSH event loop be
    # run in order to effect the upload. (See #wait.)
    def initialize(sftp, local, remote, options={}, &progress) #:nodoc:
      @sftp = sftp
      @local = local
      @remote = remote
      @progress = progress || options[:progress]
      @options = options
      @properties = options[:properties] || {}
      @active = 0

      self.logger = sftp.logger

      @uploads = []
      @recursive = if local.respond_to?(:read)
        false
      elsif ::File.symlink?(local)
        true
      else
        ::File.directory?(local)
      end

      if recursive?
        @plan = options[:plan] || Plan.build(local, remote,
          :create_root => options[:mkdir],
          :preserve_permissions => options.fetch(:preserve_permissions, true),
          :hard_links => options.fetch(:hard_links, :preserve))
        @plan.operations.each { |operation| operation.status = :pending }
        prepare_link_plan!
        @failure = nil
        @active_operations = 0
        @preflight = @plan.operations.reject { |operation| operation.action == :remove }
        @preflight = @preflight.map(&:remote).compact.uniq
        start_preflight!
      else
        raise ArgumentError, "expected a file to upload" unless local.respond_to?(:read) || ::File.exist?(local)
        @stack = [[local]]
        process_next_entry
      end
    end

    # Returns true if a directory tree is being uploaded, and false if only a
    # single file is being uploaded.
    def recursive?
      @recursive
    end

    # Returns true if the uploader is currently running. When this is false,
    # the uploader has finished processing.
    def active?
      @active > 0 || @stack.any? || (@preflight && @preflight.any?) ||
        (@plan && @plan.operations.any? { |operation| %i(pending active).include?(operation.status) })
    end

    # Forces the transfer to stop.
    def abort!
      @active = 0
      @stack.clear
      @uploads.clear
      @preflight.clear if @preflight
      if @plan
        @plan.operations.each do |operation|
          operation.status = :canceled if %i(pending active).include?(operation.status)
        end
      end
    end

    # Blocks until the upload has completed.
    def wait
      sftp.loop { active? }
      raise @failure if @failure
      self
    end

    # Returns the property with the given name. This allows Upload instances
    # to store their own state when used as part of a state machine.
    def [](name)
      @properties[name.to_sym]
    end

    # Sets the given property to the given name. This allows Upload instances
    # to store their own state when used as part of a state machine.
    def []=(name, value)
      @properties[name.to_sym] = value
    end

    private

      #--
      # "ruby -w" hates private attributes, so we have to do this longhand.
      #++

      # The progress handler for this instance. Possibly nil.
      def progress; @progress; end

      # A simple struct for recording metadata about the file currently being
      # uploaded.
      LiveFile = Struct.new(:local, :remote, :io, :size, :handle)

      # The default # of bytes to read from disk at a time.
      DEFAULT_READ_SIZE   = 32_000

      # The number of readers to use when uploading a single file.
      SINGLE_FILE_READERS = 2

      # The number of readers to use when uploading a directory.
      RECURSIVE_READERS   = 16

      def prepare_link_plan!
        if @plan.operations.any? { |operation| operation.action == :symlink } && sftp.protocol.version < 3
          raise NotImplementedError, "symbolic links require SFTP protocol version 3 or later"
        end

        hard_link_requested = @plan.operations.any? { |operation| operation.action == :hardlink }
        return unless hard_link_requested
        return if sftp.hardlink_supported?

        case options.fetch(:on_unsupported_hard_links, :raise)
        when :copy
          @plan = @plan.without_hard_links
        when :raise, :error
          raise NotImplementedError, "hard links require SFTP protocol version 6 or a hard-link extension"
        else
          raise ArgumentError, "unsupported hard link fallback: #{options[:on_unsupported_hard_links].inspect}"
        end
      end

      def start_preflight!
        @existing_directories = []
        @preflight.each do |path|
          @active += 1
          request = sftp.lstat(path, &method(:on_preflight))
          request[:remote] = path
        end
      end

      def on_preflight(response)
        @active -= 1
        path = response.request[:remote]
        @preflight.delete(path)

        if response.ok?
          verify_remote_type!(path, response[:attrs])
        elsif check_operation?(path) && [Response::FX_NO_SUCH_FILE, Response::FX_NO_SUCH_PATH].include?(response.code)
          fail_plan!(Net::SFTP::Exception.new("remote directory does not exist: #{path}"))
        elsif ![Response::FX_NO_SUCH_FILE, Response::FX_NO_SUCH_PATH].include?(response.code)
          fail_plan!(StatusException.new(response, "lstat #{path}"))
        end

        finish_preflight! if @preflight.empty?
      end

      def finish_preflight!
        return if @failure
        @plan.operations.each do |operation|
          operation.status = :succeeded if operation.action == :check
          operation.status = :succeeded if operation.action == :mkdir && @existing_directories.include?(operation.remote)
        end
        pump_planned_operations!
      end

      def verify_remote_type!(path, attrs)
        primary_actions = %i(check mkdir upload symlink hardlink)
        operation = @plan.operations.find do |candidate|
          candidate.remote == path && primary_actions.include?(candidate.action)
        end || @plan.operations.find { |candidate| candidate.remote == path }
        expected = expected_remote_type(operation)
        actual = remote_type(attrs)

        if actual && expected && actual != expected
          raise RemoteTypeConflict.new(path, expected, actual)
        end

        if actual == :directory
          @existing_directories << path
        elsif (actual == :symlink && operation.action == :symlink) ||
              (actual == :regular && operation.action == :hardlink)
          remove = @plan.operations.find do |candidate|
            candidate.action == :remove && candidate.remote == path && candidate.condition
          end
          remove.status = :pending if remove
        end
      rescue RemoteTypeConflict => conflict
        fail_plan!(conflict)
      end

      def expected_remote_type(operation)
        case operation.action
        when :mkdir, :check then :directory
        when :symlink then :symlink
        when :hardlink then :regular
        when :upload then local_remote_type(::File.lstat(operation.local))
        when :setstat then local_remote_type(::File.lstat(operation.local))
        end
      end

      def check_operation?(path)
        @plan.operations.any? { |operation| operation.action == :check && operation.remote == path }
      end

      def local_remote_type(stat)
        return :regular if stat.file?
        stat.ftype.to_sym
      end

      def remote_type(attrs)
        if attrs.permissions
          attrs.symbolic_type
        elsif attrs.respond_to?(:attributes) && attrs.attributes.key?(:type)
          type_from_attributes(attrs)
        end
      end

      def type_from_attributes(attrs)
        case attrs.attributes[:type]
        when attrs.class::T_DIRECTORY then :directory
        when attrs.class::T_SYMLINK then :symlink
        when attrs.class::T_REGULAR then :regular
        when attrs.class::T_SOCKET then :socket
        when attrs.class::T_BLOCK_DEVICE then :block_device
        when attrs.class::T_CHAR_DEVICE then :char_device
        when attrs.class::T_FIFO then :fifo
        when attrs.class::T_SPECIAL then :special
        else :unknown
        end
      end

      def pump_planned_operations!
        return if @failure

        while @active_operations < recursive_requests
          operation = next_ready_operation
          break unless operation
          start_planned_operation(operation)
        end

        if @plan.operations.none? { |operation| %i(pending active).include?(operation.status) }
          raise @failure if @failure
          update_progress(:finish)
        end
      end

      def next_ready_operation
        @plan.operations.find do |operation|
          operation.status == :pending && operation.depends_on.all? do |dependency|
            dependency = @plan.operations.find { |candidate| candidate.id == dependency }
            !dependency || %i(succeeded skipped).include?(dependency.status)
          end
        end
      end

      def start_planned_operation(operation)
        case operation.action
        when :check
          operation.status = :succeeded
          pump_planned_operations!
        when :mkdir
          operation.status = :active
          @active_operations += 1
          @active += 1
          update_progress(:mkdir, operation.remote)
          request = sftp.mkdir(operation.remote, :permissions => 0o700, &method(:on_planned_mkdir))
          request[:operation] = operation
        when :upload
          open_planned_file(operation)
        when :symlink
          run_simple_operation(operation) { create_symlink(operation.remote, operation.target) }
        when :hardlink
          run_simple_operation(operation) { sftp.hardlink(operation.remote, operation.target, &method(:on_simple_operation)) }
        when :remove
          run_simple_operation(operation) { sftp.remove(operation.remote, &method(:on_simple_operation)) }
        when :setstat
          run_simple_operation(operation) do
            sftp.setstat(operation.remote, :permissions => operation.mode, &method(:on_simple_operation))
          end
        end
      end

      def create_symlink(remote, target)
        if sftp.protocol.version >= 6
          sftp.link(remote, target, true, &method(:on_simple_operation))
        else
          sftp.symlink(target, remote, &method(:on_simple_operation))
        end
      end

      def run_simple_operation(operation)
        operation.status = :active
        @active_operations += 1
        @active += 1
        request = yield
        request[:operation] = operation
        request
      end

      def recursive_requests
        (options[:requests] || RECURSIVE_READERS).to_i
      end

      def open_planned_file(operation)
        file = ::File.open(operation.local, "rb")
        metafile = LiveFile.new(operation.local, operation.remote, file, file.stat.size)
        update_progress(:open, metafile)
        request = run_simple_operation(operation) do
          request = sftp.open(operation.remote, "w", &method(:on_planned_open))
          request
        end
        request[:file] = metafile
      rescue => error
        file&.close unless file.respond_to?(:closed?) && file.closed?
        fail_operation!(operation, error)
        pump_planned_operations!
      end

      def complete_operation!(operation, error=nil)
        @active_operations -= 1
        if error
          fail_operation!(operation, error)
        else
          operation.status = :succeeded
        end
        pump_planned_operations!
      end

      def fail_operation!(operation, error)
        operation.status = :failed
        @failure ||= error
        dependent_ids(operation.id).each do |dependent_id|
          dependent = @plan.operations.find { |candidate| candidate.id == dependent_id }
          dependent.status = :canceled
        end
      end

      def fail_plan!(error)
        @failure ||= error
        @plan.operations.each do |operation|
          operation.status = :failed if operation.status == :pending
        end
      end

      def dependent_ids(failed_id)
        result = []
        frontier = [failed_id]
        until frontier.empty?
          current = frontier.shift
          @plan.operations.each do |operation|
            next if result.include?(operation.id) || frontier.include?(operation.id)
            if operation.depends_on.include?(current)
              result << operation.id
              frontier << operation.id
            end
          end
        end
        result
      end

      def on_planned_mkdir(response)
        @active -= 1
        operation = response.request[:operation]
        error = response.ok? ? nil : StatusException.new(response, "mkdir #{operation.remote}")
        complete_operation!(operation, error)
      end

      def on_simple_operation(response)
        @active -= 1
        operation = response.request[:operation]
        error = response.ok? ? nil : StatusException.new(response, "#{operation.action} #{operation.remote}")
        complete_operation!(operation, error)
      end

      def on_planned_open(response)
        @active -= 1
        file = response.request[:file]
        operation = response.request[:operation]
        if response.ok?
          file.handle = response[:handle]
          @uploads << file
          write_planned_chunk(file, operation)
        else
          file.io.close unless file.io.nil?
          complete_operation!(operation, StatusException.new(response, "open #{file.remote}"))
        end
      end

      def on_planned_write(response)
        @active -= 1
        file = response.request[:file]
        operation = response.request[:operation]
        if response.ok?
          write_planned_chunk(file, operation)
        else
          complete_operation!(operation, StatusException.new(response, "write #{file.remote}"))
        end
      end

      def on_planned_close(response)
        @active -= 1
        file = response.request[:file]
        operation = response.request[:operation]
        error = response.ok? ? nil : StatusException.new(response, "close #{file.remote}")
        complete_operation!(operation, error)
      end

      def write_planned_chunk(file, operation)
        if file.io.nil?
          pump_planned_operations!
          return
        end

        @active += 1
        offset = file.io.pos
        data = file.io.read(options[:read_size] || DEFAULT_READ_SIZE)
        if data.nil?
          update_progress(:close, file)
          request = sftp.close(file.handle, &method(:on_planned_close))
          request[:file] = file
          request[:operation] = operation
          file.io.close
          file.io = nil
          @uploads.delete(file)
        else
          update_progress(:put, file, offset, data)
          request = sftp.write(file.handle, offset, data, &method(:on_planned_write))
          request[:file] = file
          request[:operation] = operation
        end
      end

      # Examines the stack and determines what action to take. This is the
      # starting point of the state machine.
      def process_next_entry
        if @stack.empty?
          if @uploads.any?
            write_next_chunk(@uploads.first)
          elsif !active?
            update_progress(:finish)
          end
          return false
        elsif @stack.last.empty?
          @stack.pop
          @local_cwd = ::File.dirname(@local_cwd)
          @remote_cwd = ::File.dirname(@remote_cwd)
          process_next_entry
        elsif recursive?
          entry = @stack.last.shift
          lpath = ::File.join(@local_cwd, entry)
          rpath = ::File.join(@remote_cwd, entry)

          if ::File.directory?(lpath)
            @stack.push(entries_for(lpath))
            @local_cwd = lpath
            @remote_cwd = rpath

            @active += 1
            update_progress(:mkdir, rpath)
            request = sftp.mkdir(rpath, &method(:on_mkdir))
            request[:dir] = rpath
          else
            open_file(lpath, rpath)
          end
        else
          open_file(@stack.pop.first, remote)
        end
        return true
      end

      # Prepares to send +local+ to +remote+.
      def open_file(local, remote)
        @active += 1

        if local.respond_to?(:read)
          file = local
          name = options[:name] || "<memory>"
        else
          file = ::File.open(local, "rb")
          name = local
        end

        if file.respond_to?(:stat)
          size = file.stat.size
        else
          size = file.size
        end

        metafile = LiveFile.new(name, remote, file, size)
        update_progress(:open, metafile)

        request = sftp.open(remote, "w", &method(:on_open))
        request[:file] = metafile
      end

      # Called when a +mkdir+ request finishes, successfully or otherwise.
      # If the request failed, this will raise a StatusException, otherwise
      # it will call #process_next_entry to continue the state machine.
      def on_mkdir(response)
        @active -= 1
        dir = response.request[:dir]
        raise StatusException.new(response, "mkdir #{dir}") unless response.ok?

        process_next_entry
      end

      # Called when an +open+ request finishes. Raises StatusException if the
      # open failed, otherwise it calls #write_next_chunk to begin sending
      # data to the remote server.
      def on_open(response)
        @active -= 1
        file = response.request[:file]
        raise StatusException.new(response, "open #{file.remote}") unless response.ok?

        file.handle = response[:handle]

        @uploads << file
        write_next_chunk(file)

        if !recursive?
          (options[:requests] || SINGLE_FILE_READERS).to_i.times { write_next_chunk(file) }
        end
      end

      # Called when a +write+ request finishes. Raises StatusException if the
      # write failed, otherwise it calls #write_next_chunk to continue the
      # write.
      def on_write(response)
        @active -= 1
        file = response.request[:file]
        raise StatusException.new(response, "write #{file.remote}") unless response.ok?
        write_next_chunk(file)
      end

      # Called when a +close+ request finishes. Raises a StatusException if the
      # close failed, otherwise it calls #process_next_entry to continue the
      # state machine.
      def on_close(response)
        @active -= 1
        file = response.request[:file]
        raise StatusException.new(response, "close #{file.remote}") unless response.ok?
        process_next_entry
      end

      # Attempts to send the next chunk from the given file (where +file+ is
      # a LiveFile instance).
      def write_next_chunk(file)
        if file.io.nil?
          process_next_entry
        else
          @active += 1
          offset = file.io.pos
          data = file.io.read(options[:read_size] || DEFAULT_READ_SIZE)
          if data.nil?
            update_progress(:close, file)
            request = sftp.close(file.handle, &method(:on_close))
            request[:file] = file
            file.io.close
            file.io = nil
            @uploads.delete(file)
          else
            update_progress(:put, file, offset, data)
            request = sftp.write(file.handle, offset, data, &method(:on_write))
            request[:file] = file
          end
        end
      end

      # Returns all directory entries for the given path, removing the '.'
      # and '..' relative paths.
      def entries_for(local)
        ::Dir.entries(local).reject { |v| %w(. ..).include?(v) }
      end

      # Attempts to notify the progress monitor (if one was given) about
      # progress made for the given event.
      def update_progress(event, *args)
        on = "on_#{event}"
        if progress.respond_to?(on)
          progress.send(on, self, *args)
        elsif progress.respond_to?(:call)
          progress.call(event, self, *args)
        end
      end
  end

end; end; end
