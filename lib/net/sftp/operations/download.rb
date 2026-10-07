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
  # * <tt>:read_window</tt> - the number of READ requests that may be in
  #   flight concurrently for a single file. It defaults to 1, which reads
  #   the file strictly sequentially, one request at a time. On high-latency
  #   links, increasing this allows several requests to be outstanding at
  #   once. Responses are reassembled by offset before they are written, so
  #   the destination is always written sequentially, in order.
  # * <tt>:read_buffer</tt> - the maximum number of received-but-not-yet-
  #   written bytes to buffer when :read_window is greater than 1. New
  #   requests are held back while this much data is waiting to be flushed
  #   to the destination. It defaults to read_window * read_size.
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
  #       # args[2] : data that was written
  #       puts "writing #{args[2].length} bytes to #{args[0].local} starting at #{args[1]}"
  #     when :receive then
  #       # args[0] : file metadata
  #       # args[1] : byte offset in remote file
  #       # args[2] : data that was received
  #       # (only emitted when :read_window is greater than 1; chunks may
  #       # arrive out of order, while :get always reports contiguous data)
  #       puts "received #{args[2].length} bytes from #{args[0].remote} at #{args[1]}"
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
  #     def on_receive(downloader, file, offset, data)
  #       puts "received #{data.length} bytes from #{file.remote} starting at #{offset}"
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
      @open_files = []

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
      @open_files.each do |entry|
        entry.aborted = true
        close_remote(entry)
      end
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
                         :next_offset, :pending, :buffered, :inflight, :holes,
                         :eof_at, :error, :aborted, :close_requested)

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

      # The number of READ requests that may be in flight concurrently for
      # a single file. Defaults to 1, which preserves the traditional
      # sequential read behavior.
      def read_window
        @read_window ||= [(options[:read_window] || 1).to_i, 1].max
      end

      # The maximum number of received-but-not-yet-written bytes to buffer
      # when reading a file with a :read_window greater than 1.
      def read_buffer
        options[:read_buffer] || read_window * read_size
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
        raise  StatusException.new(response, "opendir #{entry.remote}") unless response.ok?
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
        @open_files << entry
        request = sftp.open(entry.remote, &method(:on_open))
        request[:entry] = entry
      end

      # Called when a directory handle is closed.
      def on_closedir(response)
        @active -= 1
        entry = response.request[:parent]
        raise StatusException.new(response, "close #{entry.remote}") unless response.ok?
        process_next_entry
      end

      # Called when a file has been opened. This will call #download_next_chunk
      # to initiate the data transfer.
      def on_open(response)
        entry = response.request[:entry]

        if entry.aborted
          close_remote(entry, response[:handle]) if response.ok?
          return
        end

        raise StatusException.new(response, "open #{entry.remote}") unless response.ok?

        entry.handle = response[:handle]
        entry.sink = entry.local.respond_to?(:write) ? entry.local : ::File.open(entry.local, "wb")
        entry.offset = 0

        if read_window > 1
          entry.next_offset = 0
          entry.pending = {}
          entry.buffered = 0
          entry.inflight = 0
          entry.holes = []
          fill_read_window(entry)
        else
          download_next_chunk(entry)
        end
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
        return if entry.aborted

        if response.eof?
          update_progress(:close, entry)
          entry.sink.close
          close_remote(entry)
        elsif !response.ok?
          raise StatusException.new(response, "read #{entry.remote}")
        else
          entry.offset += response[:data].bytesize
          update_progress(:get, entry, response.request[:offset], response[:data])
          entry.sink.write(response[:data])
          download_next_chunk(entry)
        end
      end

      # Keeps up to #read_window READ requests in flight for the given
      # entry. Ranges left uncovered by short reads are re-requested first;
      # then new sequential ranges are requested, unless the file's end is
      # known or too much data is already waiting to be written out.
      def fill_read_window(entry)
        unless entry.aborted || entry.error
          while entry.inflight < read_window
            if entry.holes.any?
              offset, length = entry.holes.shift
            else
              break if entry.buffered >= read_buffer
              break if entry.eof_at && entry.next_offset >= entry.eof_at
              offset, length = entry.next_offset, read_size
              entry.next_offset += read_size
            end
            issue_parallel_read(entry, offset, length)
          end
        end

        maybe_finish_entry(entry)
      end

      # Initiates a single parallel read of +length+ bytes at +offset+.
      def issue_parallel_read(entry, offset, length)
        entry.inflight += 1
        request = sftp.read(entry.handle, offset, length, &method(:on_parallel_read))
        request[:entry] = entry
        request[:offset] = offset
        request[:length] = length
      end

      # Called when a parallel read finishes. Chunks are reassembled by
      # offset and only written to the sink in order; a short read is not
      # EOF, so the uncovered tail is re-requested, and an early EOF does
      # not complete the entry until all earlier ranges have arrived.
      def on_parallel_read(response)
        entry = response.request[:entry]
        entry.inflight -= 1

        unless entry.aborted || entry.error
          if response.eof?
            note_eof(entry, response.request[:offset])
          elsif !response.ok?
            entry.error = StatusException.new(response, "read #{entry.remote}")
          else
            data = response[:data]
            offset = response.request[:offset]
            if data.bytesize == 0
              note_eof(entry, offset)
            else
              note_hole(entry, offset, data.bytesize, response.request[:length])
              entry.pending[offset] = data
              entry.buffered += data.bytesize
              update_progress(:receive, entry, offset, data)
              flush_pending(entry)
            end
          end
        end

        fill_read_window(entry)
      end

      # Records that the remote end reported EOF at the given offset.
      def note_eof(entry, offset)
        entry.eof_at = offset if entry.eof_at.nil? || offset < entry.eof_at
      end

      # After a short read of +received+ bytes at +offset+ (out of
      # +requested+), schedules the still-uncovered tail to be requested
      # again, capped at the known end of the file.
      def note_hole(entry, offset, received, requested)
        return if received >= requested
        gap = requested - received
        gap = entry.eof_at - offset - received if entry.eof_at && entry.eof_at - offset - received < gap
        entry.holes << [offset + received, gap] if gap > 0
      end

      # Writes out any buffered chunks that are contiguous with the data
      # already delivered to the sink.
      def flush_pending(entry)
        while (data = entry.pending.delete(entry.offset))
          entry.buffered -= data.bytesize
          update_progress(:get, entry, entry.offset, data)
          entry.sink.write(data)
          entry.offset += data.bytesize
        end
      end

      # Closes the remote handle once the transfer of the entry is done
      # (all requested ranges delivered up to EOF) or has failed and all
      # in-flight requests have been drained or discarded.
      def maybe_finish_entry(entry)
        return if entry.close_requested || entry.inflight > 0

        if entry.error || entry.aborted
          close_remote(entry)
        elsif entry.eof_at && entry.offset >= entry.eof_at
          update_progress(:close, entry)
          entry.sink.close
          close_remote(entry)
        end
      end

      # Sends a close request for the entry's remote handle, ensuring the
      # handle is only ever closed once.
      def close_remote(entry, handle=entry.handle)
        return if entry.close_requested || handle.nil?
        entry.close_requested = true
        request = sftp.close(handle, &method(:on_close))
        request[:entry] = entry
      end

      # Called when a file handle is closed.
      def on_close(response)
        entry = response.request[:entry]
        @open_files.delete(entry)
        return if entry.aborted

        @active -= 1
        raise entry.error if entry.error
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
