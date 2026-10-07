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
  # * <tt>:read_requests</tt> - the number of concurrent read requests to use
  #   for each file. This defaults to 1, preserving sequential reads. Responses
  #   are written in offset order, and unreported data is limited to
  #   read_requests * read_size bytes.
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
  #     when :receive then
  #       # args[0] : file metadata
  #       # args[1] : byte offset in remote file
  #       # args[2] : data that was just received
  #       # args[3] : total bytes received, possibly out of order
  #       # args[4] : total contiguous bytes delivered to the destination
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
  #     def on_receive(downloader, file, offset, data, received_bytes, delivered_bytes)
  #       puts "received #{data.length} bytes at #{offset}; #{received_bytes}/#{delivered_bytes} delivered"
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
      @entries = []
      @aborted = false
      @error = nil

      self.logger = sftp.logger

      if recursive? && local.respond_to?(:write)
        raise ArgumentError, "cannot download a directory tree in-memory"
      end
      if options.key?(:read_requests) && options[:read_requests].to_i < 1
        raise ArgumentError, "read_requests must be at least 1"
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
      @aborted = true
      @stack.clear
      @entries.each { |entry| abort_entry(entry) }
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
      Entry = Struct.new(:remote, :local, :directory, :size, :handle, :offset, :sink,
        :contiguous_offset, :sent_end, :reads_in_flight, :read_ranges,
        :read_buffer, :eof_offset, :speculative_eof_offset,
        :read_state, :closing, :received_bytes,
        :delivered_bytes,
        :error, :delivering)

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

      # The number of concurrent read requests to use for one file.
      def read_requests
        options[:read_requests] || 1
      end

      # Enqueues as many files and directories from the stack as possible
      # (see #requests).
      def process_next_entry
        while stack.any? && requests > @active
          entry = stack.shift
          @active += 1
          @entries << entry

          if entry.directory
            update_progress(:mkdir, entry.local)
            ::Dir.mkdir(entry.local) unless ::File.directory?(entry.local)
            request = sftp.opendir(entry.remote, &method(:on_opendir))
            request[:entry] = entry
          else
            open_file(entry)
          end
        end

        update_progress(:finish) if !active?
      end

      # Called when a remote directory is "opened" for reading, e.g. to
      # enumerate its contents. Starts an readdir operation if the opendir
      # operation was successful.
      def on_opendir(response)
        entry = response.request[:entry]
        if !response.ok?
          @active -= 1
          raise StatusException.new(response, "opendir #{entry.remote}") unless @aborted
          process_next_entry
          return
        end

        if @aborted
          close_directory(entry, response[:handle])
          return
        end

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
          close_directory(entry, entry.handle)
        elsif !response.ok?
          fail_entry(entry, response, "readdir #{entry.remote}")
        elsif @aborted
          close_directory(entry, entry.handle)
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
        request = sftp.open(entry.remote, &method(:on_open))
        request[:entry] = entry
      end

      # Called when a directory handle is closed.
      def on_closedir(response)
        @active -= 1
        unless response.ok?
          raise StatusException.new(response, "close #{response.request[:parent].remote}") unless @aborted
          process_next_entry
          return
        end
        error = @error
        process_next_entry
        raise error if error && !active?
      end

      # Called when a file has been opened. This starts the per-file read window.
      def on_open(response)
        entry = response.request[:entry]
        if !response.ok?
          @active -= 1
          fail_entry(entry, response, "open #{entry.remote}") unless @aborted
          raise entry.error if entry.error
          process_next_entry
          return
        end

        if @aborted
          close_handle(entry, response[:handle])
          return
        end

        initialize_entry_state(entry)

        entry.handle = response[:handle]
        entry.sink = entry.local.respond_to?(:write) ? entry.local : ::File.open(entry.local, "wb")
        entry.offset = 0

        fill_reads(entry)
      end

      def initialize_entry_state(entry)
        entry.contiguous_offset = 0
        entry.sent_end = 0
        entry.reads_in_flight = 0
        entry.read_buffer = {}
        entry.read_ranges = []
        entry.eof_offset = nil
        entry.speculative_eof_offset = nil
        entry.read_state = :active
        entry.closing = false
        entry.received_bytes = 0
        entry.delivered_bytes = 0
        entry.error = nil
        entry.delivering = false
      end

      # Sends reads until the per-file window is full or the current state
      # does not permit another read.
      def fill_reads(entry)
        return unless entry.read_state == :active

        intervals = []
        scheduled = entry.reads_in_flight
        while scheduled + intervals.length < read_requests
          offset, length = next_read_interval(entry, intervals)
          break unless offset
          intervals << [offset, length]
        end

        intervals.each do |offset, length|
          entry.reads_in_flight += 1
          entry.read_ranges << [offset, offset + length]
          entry.read_ranges.sort_by!(&:first)
          entry.sent_end = [entry.sent_end, offset + length].max
          request = sftp.read(entry.handle, offset, length, &method(:on_read))
          scheduled += 1
          request[:entry] = entry
          request[:offset] = offset
          request[:length] = length
          request[:range_finish] = offset + length
        end
      end

      def next_read_interval(entry, additional_ranges=[])
        offset = entry.contiguous_offset
        max_end = entry.contiguous_offset + read_requests * read_size
        return if entry.eof_offset && offset >= entry.eof_offset
        if entry.speculative_eof_offset
          max_end = [max_end, entry.speculative_eof_offset].min
          return if offset >= max_end
        end

        ranges = reserved_ranges(entry) + additional_ranges.map do |range_offset, range_length|
          [range_offset, range_offset + range_length]
        end
        merge_ranges(ranges).each do |start, finish|
          next if finish <= offset
          break if start > max_end
          next if entry.eof_offset && finish <= entry.eof_offset
          break if entry.eof_offset && start >= entry.eof_offset

          if start > offset
            length = [read_size, start - offset, max_end - offset].min
            return [offset, length]
          end

          offset = finish
        end
        return if offset >= max_end
        return if entry.eof_offset && offset >= entry.eof_offset

        [offset, [read_size, max_end - offset].min]
      end

      def reserved_ranges(entry)
        ranges = entry.read_ranges.dup
        entry.read_buffer.each do |range_offset, data|
          ranges << [range_offset, range_offset + data.bytesize]
        end
        ranges.sort_by(&:first)
      end

      def merge_ranges(ranges)
        merged = []
        ranges.each do |start, finish|
          if merged.empty? || start > merged.last[1]
            merged << [start, finish]
          elsif finish > merged.last[1]
            merged.last[1] = finish
          end
        end
        merged
      end

      def on_read(response)
        entry = response.request[:entry]
        entry.reads_in_flight -= 1
        remove_read_range(entry, response.request[:offset],
          response.request[:range_finish])

        if entry.read_state == :aborted
          close_entry_when_drained(entry)
        else
          data = response[:data] || ""

          if response.eof?
            accept_eof(entry, response.request[:offset])
          elsif !response.ok?
            fail_entry(entry, response, "read #{entry.remote}")
          elsif entry.read_state == :error
            close_entry_when_drained(entry)
          else
            accept_data(entry, response.request[:offset], data)
          end
        end
      end

      def accept_eof(entry, offset)
        if offset != entry.contiguous_offset
          if offset < entry.contiguous_offset
            return complete_read(entry)
          else
            entry.speculative_eof_offset = offset
            complete_read(entry)
          end
          return
        elsif entry.reads_in_flight > 0
          entry.speculative_eof_offset = [offset, entry.speculative_eof_offset || offset].min
          complete_read(entry)
          return
        elsif entry.eof_offset.nil? || offset < entry.eof_offset
          entry.eof_offset = offset
        end

        entry.read_buffer.delete_if { |buffer_offset, _| buffer_offset >= entry.eof_offset }
        complete_read(entry)
      end

      def accept_data(entry, offset, data)
        length = data.bytesize

        if entry.eof_offset
          return complete_read(entry) if offset >= entry.eof_offset

          length = [length, entry.eof_offset - offset].min
          data = data.byteslice(0, length)
        end
        if entry.speculative_eof_offset && offset + length > entry.speculative_eof_offset
          entry.speculative_eof_offset = nil
        end

        entry.received_bytes += length
        update_progress(:receive, entry, offset, data, entry.received_bytes, entry.delivered_bytes) if options.key?(:read_requests)

        if offset >= entry.contiguous_offset && length > 0
          entry.read_buffer[offset] = data
          deliver_buffered_data(entry)
        end
        complete_read(entry)
      end

      def remove_read_range(entry, start, finish)
        index = entry.read_ranges.index do |range_start, range_finish|
          range_start == start && range_finish == finish
        end
        entry.read_ranges.delete_at(index) if index
      end

      def deliver_buffered_data(entry)
        return if entry.delivering

        entry.delivering = true
        while (data = entry.read_buffer.delete(entry.contiguous_offset))
          update_progress(:get, entry, entry.contiguous_offset, data)
          entry.sink.write(data)
          entry.contiguous_offset += data.bytesize
          entry.delivered_bytes = entry.contiguous_offset
          if entry.speculative_eof_offset && entry.contiguous_offset == entry.speculative_eof_offset
            entry.eof_offset = entry.contiguous_offset
          end
        end
        entry.delivering = false
      end

      def complete_read(entry)
        deliver_buffered_data(entry) if entry.read_state == :active
        fill_reads(entry) if entry.read_state == :active && !entry.delivering
        close_entry_when_drained(entry)
      end

      def close_entry_when_drained(entry)
        return unless entry.handle
        return if entry.closing || entry.reads_in_flight > 0
        return unless entry.read_state == :aborted || entry.read_state == :error ||
          (entry.eof_offset && entry.contiguous_offset == entry.eof_offset)

        close_handle(entry, entry.handle)
      end

      def close_handle(entry, handle)
        return if entry.closing

        entry.closing = true
        entry.read_state ||= :closing
        update_progress(:close, entry) if entry.sink
        entry.sink.close if entry.sink
        request = sftp.close(handle, &method(:on_close))
        request[:entry] = entry
      end

      def close_directory(entry, handle)
        return if entry.closing

        entry.closing = true
        request = sftp.close(handle, &method(:on_closedir))
        request[:parent] = entry
      end

      def abort_entry(entry)
        return if entry.closing

        if entry.directory
          close_directory(entry, entry.handle) if entry.handle
          return
        end

        return unless entry.read_state

        entry.read_state = :aborted
        entry.read_buffer.clear
        entry.eof_offset = nil
        entry.speculative_eof_offset = nil
        close_entry_when_drained(entry)
      end

      def fail_entry(entry, response, description)
        entry.read_state ||= :error
        entry.read_buffer.clear if entry.read_buffer
        entry.error = StatusException.new(response, description)
        @error ||= entry.error
        @aborted = true
        @stack.clear
        @entries.each { |other| abort_entry(other) unless other.equal?(entry) }

        if entry.handle
          entry.read_state = :error
          close_entry_when_drained(entry)
        else
          @active -= 1
          process_next_entry
        end
      end

      # Called when a file handle is closed.
      def on_close(response)
        entry = response.request[:entry]
        @active -= 1
        if !response.ok? && !@aborted
          raise StatusException.new(response, "close #{entry.remote}")
        end

        error = @error
        if entry.read_state == :error && error.nil?
          error = entry.error
          @error = error
        end
        process_next_entry
        raise error if error && !active?
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
