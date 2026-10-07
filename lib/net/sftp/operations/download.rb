require 'net/ssh/loggable'

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
  # When the server advertises the +limits@openssh.com+ extension, read
  # requests are additionally capped by the negotiated read limit (with
  # packet encoding overhead subtracted), files and directories share the
  # negotiated handle budget, and traversal reserves a slot so pending
  # directories never occupy the entire budget. See Net::SFTP::Limits and
  # Net::SFTP::Session#limits.
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

    # The number of file and directory handles currently held open on the
    # server. Files and directories share the server's single handle budget.
    attr_reader :open_handles

    # The greatest number of simultaneously open (or opening) handles
    # observed so far. Useful for verifying that the server's handle limit
    # was respected.
    attr_reader :peak_open_handles

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
      @open_handles = 0
      @opening_handles = 0
      @peak_open_handles = 0

      self.logger = sftp.logger

      if recursive? && local.respond_to?(:write)
        raise ArgumentError, "cannot download a directory tree in-memory"
      end

      @stack = [Entry.new(remote, local, recursive?)]
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
      Entry = Struct.new(:remote, :local, :directory, :size, :handle, :offset, :sink)

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

      # The number of bytes to request from the server in a single FXP_READ,
      # bounded by the negotiated read limit and accounting for packet
      # encoding overhead of the FXP_DATA reply. A FXP_READ request does
      # not include the data, so its handle length does not affect the
      # payload length; +handle+ is accepted for symmetry with writes.
      def read_chunk_size(handle)
        wanted = read_size
        if sftp.limits
          sftp.limits.read_length(wanted, handle)
        else
          wanted
        end
      end

      # Number of handle slots currently committed: open handles plus open
      # or opendir requests still in flight. This is what the budget is
      # checked against, since a waiting opendir's slot must count even
      # before its handle comes back.
      def reserved_handles
        @open_handles + @opening_handles
      end

      # Reserve a handle slot immediately before an FXP_OPEN or FXP_OPENDIR
      # request is dispatched. The reservation turns into an open handle
      # when the opening reply arrives (see #on_open/#on_opendir) and is
      # finally released on close (see #on_close/#on_closedir).
      def reserve_handle!
        @opening_handles += 1
      end

      # Marks a reserved slot as backed by an actual server handle; it
      # remains occupied until the handle is closed.
      def confirm_handle!
        @opening_handles -= 1
        @open_handles += 1
        @peak_open_handles = [@peak_open_handles, @open_handles].max
      end

      # Cancels a reservation for an opening request that failed, freeing
      # the slot without ever holding a handle.
      def cancel_reserved_handle!
        @opening_handles -= 1
      end

      # Release the slot held by a closed handle.
      def release_handle!
        @open_handles -= 1
      end

      # Returns true if a handle slot is available for a file.
      def file_handle_available?
        sftp.limits.nil? || reserved_handles < sftp.limits.max_open_handles
      end

      # Returns true if a handle slot is available for the directory +entry+.
      # Files and directories share the handle budget. Opening a directory
      # is permitted only when at least one other slot remains free after it
      # opens, so that in-progress traversals can always open files (or
      # another directory) instead of stalling with every slot occupied by
      # waiting directories. The reserved slot is waived when the directory
      # is the only pending entry (e.g. a root directory on a one-handle
      # server), since opening it is the only way to make progress.
      def directory_handle_available?(entry)
        return true if sftp.limits.nil?
        reserved_handles + 1 < sftp.limits.max_open_handles || stack == [entry]
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
          entry = next_dispatchable_entry
          break unless entry
          stack.delete(entry)
          @active += 1

          if entry.directory
            update_progress(:mkdir, entry.local)
            ::Dir.mkdir(entry.local) unless ::File.directory?(entry.local)
            reserve_handle!
            request = sftp.opendir(entry.remote, &method(:on_opendir))
            request[:entry] = entry
          else
            open_file(entry)
          end
        end

        update_progress(:finish) if !active?
      end

      # Picks the next stack entry whose opening fits the current handle
      # budget. A blocked file is skipped so a later directory can use an
      # available slot. A blocked directory always stops the scan: later
      # entries are siblings waiting on traversal progress, and consuming
      # the reserved last slot with any of them would allow waiting
      # directories to occupy the entire handle budget.
      def next_dispatchable_entry
        stack.each do |entry|
          available = entry.directory ? directory_handle_available?(entry) : file_handle_available?
          return entry if available
          return nil if entry.directory
        end
        nil
      end

      # Called when a remote directory is "opened" for reading, e.g. to
      # enumerate its contents. Starts an readdir operation if the opendir
      # operation was successful.
      def on_opendir(response)
        entry = response.request[:entry]
        unless response.ok?
          cancel_reserved_handle!
          raise StatusException.new(response, "opendir #{entry.remote}")
        end
        confirm_handle!
        entry.handle = response[:handle]
        request = sftp.readdir(response[:handle], &method(:on_readdir))
        request[:parent] = entry
      end

      # Called when the next batch of items is read from a directory on the
      # remote server. If any items were read, they are added to the queue
      # and #process_next_entry is called.
      def on_readdir(response)
        entry = response.request[:parent]
        if response.eof?
          request = sftp.close(entry.handle, &method(:on_closedir))
          request[:parent] = entry
        elsif !response.ok?
          raise StatusException.new(response, "readdir #{entry.remote}")
        else
          response[:names].each do |item|
            next if item.name == "." || item.name == ".."
            stack << Entry.new(::File.join(entry.remote, item.name), ::File.join(entry.local, item.name), item.directory?, item.attributes.size)
          end

          # take this opportunity to enqueue more requests
          process_next_entry

          request = sftp.readdir(entry.handle, &method(:on_readdir))
          request[:parent] = entry
        end
      end

      # Called when a file is to be opened for reading from the remote server.
      def open_file(entry)
        update_progress(:open, entry)
        reserve_handle!
        request = sftp.open(entry.remote, &method(:on_open))
        request[:entry] = entry
      end

      # Called when a directory handle is closed.
      def on_closedir(response)
        @active -= 1
        entry = response.request[:parent]
        if response.ok?
          release_handle!
        else
          raise StatusException.new(response, "close #{entry.remote}")
        end
        process_next_entry
      end

      # Called when a file has been opened. This will call #download_next_chunk
      # to initiate the data transfer.
      def on_open(response)
        entry = response.request[:entry]
        unless response.ok?
          @active -= 1
          cancel_reserved_handle!
          raise StatusException.new(response, "open #{entry.remote}")
        end
        confirm_handle!

        entry.handle = response[:handle]
        entry.sink = entry.local.respond_to?(:write) ? entry.local : ::File.open(entry.local, "wb")
        entry.offset = 0

        download_next_chunk(entry)
      end

      # Initiates a read of the next #read_size bytes from the file.
      def download_next_chunk(entry)
        length = read_chunk_size(entry.handle)
        request = sftp.read(entry.handle, entry.offset, length, &method(:on_read))
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
        if response.ok?
          release_handle!
        else
          raise StatusException.new(response, "close #{entry.remote}")
        end
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
