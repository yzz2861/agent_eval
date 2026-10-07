require 'net/ssh/loggable'
require 'net/sftp/errors'
require 'net/sftp/operations/name_mapper'
require 'net/sftp/operations/name_manifest'

module Net; module SFTP; module Operations

  # A general purpose downloader module for Net::SFTP. It can download files
  # into IO objects, or directly to files on the local file system. It can
  # even download entire directory trees via SFTP, and provides a flexible
  # progress reporting mechanism.
  #
  # To download a single file from the remote server, simply specify both the
  # remote and local paths:
  #
  #   downloader = sftp.download("/path/to/remote.txt", "/path/to/local.txt")
  #
  # By default, this operates asynchronously, so if you want to block until
  # the download finishes, you can use the 'bang' variant:
  #
  #   sftp.download!("/path/to/remote.txt", "/path/to/local.txt")
  #
  # Or, if you have multiple downloads that you want to run in parallel, you can
  # employ the #wait method of the returned object:
  #
  #   dls = %w(file1 file2 file3).map { |f| sftp.download("remote/#{f}", f) }
  #   dls.each { |d| d.wait }
  #
  # To download an entire directory tree, recursively, simply specify :recursive => true:
  #
  #   sftp.download!("/path/to/remotedir", "/path/to/local", :recursive => true)
  #
  # This will download "/path/to/remotedir", its contents, its subdirectories,
  # and their contents, recursively, to "/path/to/local" on the local host.
  # (If you specify :recursive => true and the source is not a directory,
  # you'll get an error!)
  #
  # If you want to pull the contents of a file on the remote server, and store
  # the data in memory rather than immediately to disk, you can pass an IO
  # object as the destination:
  #
  #   require 'stringio'
  #   io = StringIO.new
  #   sftp.download!("/path/to/remote", io)
  #
  # This will only work for single-file downloads. Trying to do so with
  # :recursive => true will cause an error.
  #
  # === Downloading directories with unsafe remote names
  #
  # A remote file system may allow several names that cannot coexist on the
  # local host (names differing only by case, by Unicode normalization, or
  # containing invalid UTF-8, path separators or platform reserved names).
  # Recursive downloads therefore pass every directory layer through an
  # explicit Net::SFTP::Operations::NameMapper. The original remote bytes are
  # preserved as the identity of each entry and are recorded in a
  # reverse-lookup manifest (see Net::SFTP::Operations::NameManifest).
  #
  # All names within a directory are validated together, and the contents of
  # a directory are only written after the whole layer is known to be safe;
  # consequently a rejected layer never overwrites or truncates an existing
  # local file.
  #
  # Relevant options:
  #
  # * <tt>:name_mapper</tt> - a Net::SFTP::Operations::NameMapper instance,
  #   or a hash of options used to construct one (the default rejects unsafe
  #   names). Pass :strategy => :escape to percent-encode problematic bytes
  #   reversibly instead. Pass <tt>:manifest_name => false</tt> to suppress
  #   the manifest.
  # * <tt>:name_equivalency</tt> - shortcut for the NameMapper
  #   <tt>:equivalency</tt> option: a callable used to derive the collision
  #   key of mapped names, allowing the behavior of foreign file systems
  #   (case folding, Unicode normalization) to be emulated without relying
  #   on the local host. See Net::SFTP::Operations::NameMapper::CASE_FOLD and
  #   friends.
  #
# The following options are supported:
  #
  # * <tt>:progress</tt> - either a block or an object to act as a progress
  #   callback. See the discussion of "progress monitoring" below.
  # * <tt>:requests</tt> - the number of pending SFTP requests to allow at
  #   any given time. When downloading an entire directory tree recursively,
  #   this will default to 16. Setting this higher might improve throughput.
  #   Reducing it will reduce throughput.
  # * <tt>:read_size</tt> - the maximum number of bytes to read at a time
  #   from the source. Increasing this value might improve throughput. It
  #   defaults to 32,000 bytes.
  #
  # == Progress Monitoring
  #
  # Sometimes it is desirable to track the progress of a download. There are
  # two ways to do this: either using a callback block, or a special custom
  # object.
  #
  # Using a block it's pretty straightforward:
  #
  #   sftp.download!("remote", "local") do |event, downloader, *args|
  #     case event
  #     when :open then
  #       # args[0] : file metadata
  #       puts "starting download: #{args[0].remote} -> #{args[0].local} (#{args[0].size} bytes}"
  #     when :get then
  #       # args[0] : file metadata
  #       # args[1] : byte offset in remote file
  #       # args[2] : data that was received
  #       puts "writing #{args[2].length} bytes to #{args[0].local} starting at #{args[1]}"
  #     when :close then
  #       # args[0] : file metadata
  #       puts "finished with #{args[0].remote}"
  #     when :mkdir then
  #       # args[0] : local path name
  #       puts "creating directory #{args[0]}"
  #     when :finish then
  #       puts "all done!"
  #     end
  #   end
  #
  # However, for more complex implementations (e.g., GUI interfaces and such)
  # a block can become cumbersome. In those cases, you can create custom
  # handler objects that respond to certain methods, and then pass your handler
  # to the downloader:
  #
  #   class CustomHandler
  #     def on_open(downloader, file)
  #       puts "starting download: #{file.remote} -> #{file.local} (#{file.size} bytes)"
  #     end
  #
  #     def on_get(downloader, file, offset, data)
  #       puts "writing #{data.length} bytes to #{file.local} starting at #{offset}"
  #     end
  #
  #     def on_close(downloader, file)
  #       puts "finished with #{file.remote}"
  #     end
  #
  #     def on_mkdir(downloader, path)
  #       puts "creating directory #{path}"
  #     end
  #
  #     def on_finish(downloader)
  #       puts "all done!"
  #     end
  #   end
  #
  #   sftp.download!("remote", "local", :progress => CustomHandler.new)
  #
  # If you omit any of those methods, the progress updates for those missing
  # events will be ignored. You can create a catchall method named "call" for
  # those, instead.
  class Download
    include Net::SSH::Loggable

    # The destination of the download (the name of a file or directory on
    # the local server, or an IO object)
    attr_reader :local

    # The source of the download (the name of a file or directory on the
    # remote server)
    attr_reader :remote

    # The hash of options that was given to this Download instance.
    attr_reader :options

    # The SFTP session instance that drives this download.
    attr_reader :sftp

    # The properties hash for this object
    attr_reader :properties

    # Instantiates a new downloader process on top of the given SFTP session.
    # +local+ is either an IO object that should receive the data, or a string
    # identifying the target file or directory on the local host. +remote+ is
    # a string identifying the location on the remote host that the download
    # should source.
    #
    # This will return immediately, and requires that the SSH event loop be
    # run in order to effect the download. (See #wait.)
    def initialize(sftp, local, remote, options={}, &progress)
      @sftp = sftp
      @local = local
      @remote = remote
      @progress = progress || options[:progress]
      @options = options
      @active = 0
      @properties = options[:properties] || {}

      self.logger = sftp.logger

      if recursive? && local.respond_to?(:write)
        raise ArgumentError, "cannot download a directory tree in-memory"
      end

      @stack = [Entry.new(remote, local, recursive?)]
      @manifest = build_manifest if recursive?
      process_next_entry
    end

    # Returns the value of the :recursive key in the options hash that was
    # given when the object was instantiated.
    def recursive?
      options[:recursive]
    end

    # Returns true if there are any active requests or pending files or
    # directories.
    def active?
      @active > 0 || stack.any?
    end

    # Forces the transfer to stop.
    def abort!
      @active = 0
      @stack.clear
    end

    # Runs the SSH event loop for as long as the downloader is active (see
    # #active?). This can be used to block until the download completes.
    def wait
      sftp.loop { active? }
      self
    end

    # Returns the property with the given name. This allows Download instances
    # to store their own state when used as part of a state machine.
    def [](name)
      @properties[name.to_sym]
    end

    # Sets the given property to the given name. This allows Download instances
    # to store their own state when used as part of a state machine.
    def []=(name, value)
      @properties[name.to_sym] = value
    end

    private

      # A simple struct for encapsulating information about a single remote
      # file or directory that needs to be downloaded.
      Entry = Struct.new(:remote, :local, :directory, :size, :handle, :offset, :sink, :relative, :pending_names)
 
      # Builds the NameMapper used to translate remote entry names into
      # locally representable names.
      def name_mapper
        @name_mapper ||= begin
          given = options[:name_mapper]
          if given.is_a?(NameMapper)
            given
          else
            mapper_options = given.is_a?(Hash) ? given.dup : {}
            mapper_options[:equivalency] ||= options[:name_equivalency] if options[:name_equivalency]
            NameMapper.new(mapper_options)
          end
        end
      end
 
      # The reverse-lookup manifest accumulator for this download.
      attr_reader :manifest
 
      def build_manifest
        NameManifest.new(name_mapper, local)
      end

      #--
      # "ruby -w" hates private attributes, so we have to do these longhand
      #++

      # The stack of Entry instances, indicating which files and directories
      # on the remote host remain to be downloaded.
      def stack; @stack; end

      # The progress handler for this instance. Possibly nil.
      def progress; @progress; end

      # The default read size.
      DEFAULT_READ_SIZE = 32_000

      # The number of bytes to read at a time from remote files.
      def read_size
        options[:read_size] || DEFAULT_READ_SIZE
      end

      # The number of simultaneou SFTP requests to use to effect the download.
      # Defaults to 16 for recursive downloads.
      def requests
        options[:requests] || (recursive? ? 16 : 2)
      end

      # Enqueues as many files and directories from the stack as possible
      # (see #requests).
      def process_next_entry
        while stack.any? && requests > @active
          entry = stack.shift
          @active += 1

          if entry.directory
            update_progress(:mkdir, entry.local)
            ::Dir.mkdir(entry.local) unless ::File.directory?(entry.local)
            entry.pending_names = []
            request = sftp.opendir(entry.remote, &method(:on_opendir))
            request[:entry] = entry
          else
            open_file(entry)
          end
        end

        if !active?
          write_manifest!
          update_progress(:finish)
        end
      end

      # Persists the reverse-lookup manifest once every entry has been
      # written. The manifest basename passed the top-level collision check
      # along with all real remote entries.
      def write_manifest!
        return unless manifest && name_mapper.manifest_name
        return if @manifest_written
        @manifest_written = true
        update_progress(:manifest, manifest.write!)
      end

      # Called when a remote directory is "opened" for reading, e.g. to
      # enumerate its contents. Starts an readdir operation if the opendir
      # operation was successful.
      def on_opendir(response)
        entry = response.request[:entry]
        raise  StatusException.new(response, "opendir #{entry.remote}") unless response.ok?
        entry.handle = response[:handle]
        request = sftp.readdir(response[:handle], &method(:on_readdir))
        request[:parent] = entry
      end

      # Called when the next batch of items is read from a directory on the
      # remote server. Items are buffered until the full directory has been
      # enumerated (EOF), at which point #on_closedir maps and commits the
      # whole layer before any child entry is written.
      def on_readdir(response)
        entry = response.request[:parent]
        if response.eof?
          request = sftp.close(entry.handle, &method(:on_closedir))
          request[:parent] = entry
        elsif !response.ok?
          raise StatusException.new(response, "readdir #{entry.remote}")
        else
          response[:names].each do |item|
            entry.pending_names << item
          end

          request = sftp.readdir(entry.handle, &method(:on_readdir))
          request[:parent] = entry
        end
      end

      # Called when all entries of a remote directory have been enumerated.
      # Maps the complete layer before anything within it is written:
      # subdirectories are created and file open requests are enqueued only
      # after every name in the layer passed validation and collision
      # checking. The manifest name participates in the top-level check.
      def commit_directory_layer(entry)
        items = entry.pending_names
        raw_names = items.reject { |item| item.name == "." || item.name == ".." }
                          .map { |item| raw_name(item.name) }

        top_level = entry.relative.nil?
        mapped = name_mapper.map(raw_names, top_level)

        items.each do |item|
          next if item.name == "." || item.name == ".."
          bytes = raw_name(item.name)
          mapped_name = mapped.assoc(bytes).last
          child_remote = join_remote(entry.remote, bytes)
          child_local = ::File.join(entry.local, mapped_name)
          child_relative = entry.relative.nil? ? mapped_name : ::File.join(entry.relative, mapped_name)

          manifest.add(child_relative, child_remote, bytes, item.directory? ? :directory : :file)

          if item.directory?
            update_progress(:mkdir, child_local)
            ::Dir.mkdir(child_local) unless ::File.directory?(child_local)
          end

          stack << Entry.new(child_remote, child_local, item.directory?, item.attributes.size, nil, nil, nil, child_relative, [])
        end
      end

      # Remote names are opaque SFTP strings; keep them as raw bytes so that
      # invalid UTF-8 remains the entry's identity rather than being scrubbed
      # into replacement characters.
      def raw_name(name)
        String(name).dup.force_encoding(Encoding::ASCII_8BIT)
      end

      # Remote paths are defined by the SFTP protocol with "/" as the
      # separator and must preserve raw bytes; never mix them with UTF-8
      # local names through File.join (which may enforce encoding
      # compatibility).
      def join_remote(parent, name)
        parent_bytes = String(parent).b
        separator = parent_bytes.end_with?("/".b) ? String.new.force_encoding(Encoding::ASCII_8BIT) : "/".b
        parent_bytes + separator + String(name).b
      end

      # Called when a file is to be opened for reading from the remote server.
      def open_file(entry)
        update_progress(:open, entry)
        request = sftp.open(entry.remote, &method(:on_open))
        request[:entry] = entry
      end

      # Called when a directory handle is closed.
      def on_closedir(response)
        @active -= 1
        entry = response.request[:parent]
        raise StatusException.new(response, "close #{entry.remote}") unless response.ok?
        commit_directory_layer(entry)
        process_next_entry
      end

      # Called when a file has been opened. This will call #download_next_chunk
      # to initiate the data transfer.
      def on_open(response)
        entry = response.request[:entry]
        raise StatusException.new(response, "open #{entry.remote}") unless response.ok?

        entry.handle = response[:handle]
        entry.sink = entry.local.respond_to?(:write) ? entry.local : ::File.open(entry.local, "wb")
        entry.offset = 0

        download_next_chunk(entry)
      end

      # Initiates a read of the next #read_size bytes from the file.
      def download_next_chunk(entry)
        request = sftp.read(entry.handle, entry.offset, read_size, &method(:on_read))
        request[:entry] = entry
        request[:offset] = entry.offset
      end

      # Called when a read from a file finishes. If the read was successful
      # and returned data, this will call #download_next_chunk to read the
      # next bit from the file. Otherwise the file will be closed.
      def on_read(response)
        entry = response.request[:entry]

        if response.eof?
          update_progress(:close, entry)
          entry.sink.close
          request = sftp.close(entry.handle, &method(:on_close))
          request[:entry] = entry
        elsif !response.ok?
          raise StatusException.new(response, "read #{entry.remote}")
        else
          entry.offset += response[:data].bytesize
          update_progress(:get, entry, response.request[:offset], response[:data])
          entry.sink.write(response[:data])
          download_next_chunk(entry)
        end
      end

      # Called when a file handle is closed.
      def on_close(response)
        @active -= 1
        entry = response.request[:entry]
        raise StatusException.new(response, "close #{entry.remote}") unless response.ok?
        process_next_entry
      end

      # If a progress callback or object has been set, this will report
      # the progress to that callback or object.
      def update_progress(hook, *args)
        on = "on_#{hook}"
        if progress.respond_to?(on)
          progress.send(on, self, *args)
        elsif progress.respond_to?(:call)
          progress.call(hook, self, *args)
        end
      end
  end

end; end; end
