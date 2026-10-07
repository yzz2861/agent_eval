require 'net/ssh/loggable'

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
  # * <tt>:sparse</tt> - either +true+, or a Hash of sparse options. When
  #   enabled, the uploader scans the local source for runs of zero bytes
  #   and skips sending them, issuing WRITE requests only for the data
  #   extents. This reduces network traffic for sources with large zero
  #   regions (like backup images); it does not, however, guarantee that
  #   the server will allocate the skipped regions sparsely on disk. The
  #   remote file is always opened with truncation, so overwriting an
  #   existing remote file cannot leave stale bytes inside the skipped
  #   holes, and when the local source ends with a skipped zero region the
  #   remote logical size is forced to the correct value via FXP_FSETSTAT.
  #   The following sub-options are supported when a Hash is given:
  #
  #   * <tt>:min_hole</tt> - the minimum number of consecutive zero bytes
  #     that will be skipped; shorter runs are sent literally. Defaults to
  #     32,768 bytes.
  #   * <tt>:extents</tt> - an explicit list of <tt>[offset, length]</tt>
  #     data extents to send, instead of scanning the source. Extents must
  #     be sorted by offset, must not overlap, and must lie entirely within
  #     the bounds of the local source. This requires a seekable source.
  #
  #   Sparse mode adds two progress events (see below): <tt>:skip</tt>,
  #   which reports a zero region that was not sent, and <tt>:resize</tt>,
  #   which reports the logical size the remote file is set to when it ends
  #   with a skipped zero region. Together with <tt>:put</tt> (which reports
  #   the bytes actually sent), these let observers track logical bytes and
  #   sent bytes separately.
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
  #     when :skip then
  #       # args[0] : file metadata
  #       # args[1] : byte offset in remote file
  #       # args[2] : length of the zero region that was skipped (sparse mode)
  #       puts "skipping #{args[2]} zero bytes at #{args[1]}"
  #     when :resize then
  #       # args[0] : file metadata
  #       # args[1] : logical size the remote file is set to (sparse mode)
  #       puts "setting remote size to #{args[1]}"
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
      @recursive = local.respond_to?(:read) ? false : ::File.directory?(local)

      if recursive?
        @stack = [entries_for(local)]
        @local_cwd = local
        @remote_cwd = remote

        @active += 1
        if @options[:mkdir]
          sftp.mkdir(remote) do |response|
            @active -= 1
            raise StatusException.new(response, "mkdir `#{remote}'") unless response.ok?
            (options[:requests] || RECURSIVE_READERS).to_i.times do
              break unless process_next_entry
            end
          end
        else
          @active -= 1
          process_next_entry
        end
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
      @active > 0 || @stack.any?
    end

    # Forces the transfer to stop.
    def abort!
      @active = 0
      @stack.clear
      @uploads.clear
    end

    # Blocks until the upload has completed.
    def wait
      sftp.loop { active? }
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
      LiveFile = Struct.new(:local, :remote, :io, :size, :handle, :sparse)

      # Internal state for a sparse upload. Tracks the scan position, the
      # pending (not yet sent) data, and any in-progress zero run.
      SparseState = Struct.new(:min_hole, :extents, :extent_index,
        :extent_remaining, :pending, :pending_start, :zero_run, :in_hole,
        :hole_start, :pos, :ready, :eof, :resize_to, :done, :tail_reported)

      # The default # of bytes to read from disk at a time.
      DEFAULT_READ_SIZE   = 32_000

      # The default minimum number of consecutive zero bytes that sparse
      # mode will skip instead of sending.
      DEFAULT_MIN_HOLE_SIZE = 32_768

      # The number of readers to use when uploading a single file.
      SINGLE_FILE_READERS = 2

      # The number of readers to use when uploading a directory.
      RECURSIVE_READERS   = 16

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
        prepare_sparse(metafile) if sparse_options
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

      # Called when a +fsetstat+ request finishes. Raises StatusException if
      # it failed, otherwise closes the file to finish the upload.
      def on_fsetstat(response)
        @active -= 1
        file = response.request[:file]
        raise StatusException.new(response, "fsetstat #{file.remote}") unless response.ok?

        @active += 1
        close_file(file)
      end

      # Attempts to send the next chunk from the given file (where +file+ is
      # a LiveFile instance).
      def write_next_chunk(file)
        if file.io.nil?
          process_next_entry
        else
          @active += 1
          if file.sparse
            write_next_sparse_chunk(file)
          else
            offset = file.io.pos
            data = file.io.read(read_size)
            if data.nil?
              close_file(file)
            else
              update_progress(:put, file, offset, data)
              request = sftp.write(file.handle, offset, data, &method(:on_write))
              request[:file] = file
            end
          end
        end
      end

      # Sends the next data extent of a sparse upload, skipping any zero
      # regions. When no data remains, the remote file is resized (if the
      # tail was a skipped zero region) and then closed.
      def write_next_sparse_chunk(file)
        state = file.sparse
        if state.done
          @active -= 1
          return
        end

        segment = next_data_segment(file)
        if segment.nil?
          state.done = true
          if state.resize_to
            update_progress(:resize, file, state.resize_to)
            request = sftp.fsetstat(file.handle, {:size => state.resize_to}, &method(:on_fsetstat))
            request[:file] = file
          else
            close_file(file)
          end
        else
          offset, data = segment
          update_progress(:put, file, offset, data)
          request = sftp.write(file.handle, offset, data, &method(:on_write))
          request[:file] = file
        end
      end

      # Closes the remote file and the local source, and removes the file
      # from the list of active uploads.
      def close_file(file)
        update_progress(:close, file)
        request = sftp.close(file.handle, &method(:on_close))
        request[:file] = file
        file.io.close
        file.io = nil
        @uploads.delete(file)
      end

      # The normalized :sparse option value: nil when sparse mode is
      # disabled, or a Hash of sparse sub-options.
      def sparse_options
        case value = options[:sparse]
        when nil, false then nil
        when true then {}
        when Hash then value
        else raise ArgumentError, ":sparse must be true or an options Hash"
        end
      end

      # The number of bytes to read from the local source at a time.
      def read_size
        options[:read_size] || DEFAULT_READ_SIZE
      end

      # Initializes the sparse scan state for the given file.
      def prepare_sparse(file)
        min_hole = (sparse_options[:min_hole] || DEFAULT_MIN_HOLE_SIZE).to_i
        raise ArgumentError, ":min_hole must be a positive integer" if min_hole <= 0

        state = SparseState.new
        state.min_hole = min_hole
        state.pending = +""
        state.pending_start = 0
        state.zero_run = 0
        state.in_hole = false
        state.pos = 0
        state.ready = []
        state.eof = false

        extents = sparse_options[:extents]
        if extents
          unless file.io.respond_to?(:seek)
            raise ArgumentError, ":extents requires a seekable local source"
          end
          state.extents = validate_extents(extents, file.size)
          state.extent_index = 0
          state.extent_remaining = 0
        end

        file.sparse = state
      end

      # Validates a caller-provided extent table, returning a normalized
      # list of [offset, length] pairs. Raises ArgumentError if the extents
      # are unsorted, overlapping, or out of bounds.
      def validate_extents(extents, size)
        list = extents.map do |extent|
          offset, length = extent
          offset = Integer(offset)
          length = Integer(length)
          raise ArgumentError, "sparse extent offset must be non-negative" if offset < 0
          raise ArgumentError, "sparse extent length must be positive" if length <= 0
          raise ArgumentError, "sparse extent exceeds local size" if offset + length > size
          [offset, length]
        end

        previous_end = 0
        list.each do |offset, length|
          if offset < previous_end
            raise ArgumentError, "sparse extents must be sorted by offset and non-overlapping"
          end
          previous_end = offset + length
        end

        list
      end

      # Returns the next [offset, data] segment to send for a sparse
      # upload, or nil when no data remains.
      def next_data_segment(file)
        if file.sparse.extents
          next_extent_segment(file)
        else
          next_scanned_segment(file)
        end
      end

      # Returns the next [offset, data] segment for a caller-provided
      # extent table, seeking the local source between extents. Gaps
      # between extents are reported via the :skip progress event.
      def next_extent_segment(file)
        state = file.sparse
        loop do
          if state.extent_remaining && state.extent_remaining > 0
            offset = state.pos
            data = file.io.read([read_size, state.extent_remaining].min)
            raise IOError, "local source ended before all sparse extents were read" if data.nil?
            state.pos += data.bytesize
            state.extent_remaining -= data.bytesize
            return [offset, data]
          end

          if state.extent_index >= state.extents.length
            unless state.tail_reported
              state.tail_reported = true
              if state.pos < file.size
                update_progress(:skip, file, state.pos, file.size - state.pos)
                state.resize_to = file.size
              end
            end
            return nil
          end

          offset, length = state.extents[state.extent_index]
          state.extent_index += 1
          update_progress(:skip, file, state.pos, offset - state.pos) if offset > state.pos
          file.io.seek(offset)
          state.pos = offset
          state.extent_remaining = length
        end
      end

      # Returns the next [offset, data] segment by scanning the local
      # source for zero regions. Zero runs of at least :min_hole bytes are
      # skipped (and reported via the :skip progress event); shorter runs
      # are sent literally as part of the surrounding data.
      def next_scanned_segment(file)
        state = file.sparse
        loop do
          return state.ready.shift unless state.ready.empty?

          if state.pending.bytesize >= read_size
            segment = [state.pending_start, state.pending]
            state.pending_start += state.pending.bytesize
            state.pending = +""
            return segment
          end

          break if state.eof

          chunk = file.io.read(read_size)
          if chunk.nil?
            finalize_scan(file)
          else
            scan_chunk(file, chunk)
          end
        end
        nil
      end

      # Scans a chunk of local data, splitting it into zero and non-zero
      # runs. Zero runs that cross read-block boundaries are merged into a
      # single hole.
      def scan_chunk(file, chunk)
        state = file.sparse
        chunk = chunk.b
        offset = state.pos
        state.pos += chunk.bytesize
        chunk.scan(/\x00+|[^\x00]+/) do |run|
          if run.getbyte(0) == 0
            consume_zeros(file, offset, run.bytesize)
          else
            consume_data(file, offset, run)
          end
          offset += run.bytesize
        end
      end

      # Accumulates a run of zero bytes. When the run reaches :min_hole
      # bytes, any pending data is flushed as a segment and the run becomes
      # a skippable hole.
      def consume_zeros(file, offset, length)
        state = file.sparse
        return if state.in_hole

        state.zero_run += length
        if state.zero_run >= state.min_hole
          if state.pending.bytesize > 0
            state.ready << [state.pending_start, state.pending]
            state.pending = +""
          end
          state.in_hole = true
          state.hole_start = offset + length - state.zero_run
          state.zero_run = 0
        end
      end

      # Accumulates a run of non-zero data, closing (and reporting) any
      # in-progress hole first.
      def consume_data(file, offset, data)
        state = file.sparse
        if state.in_hole
          update_progress(:skip, file, state.hole_start, offset - state.hole_start)
          state.in_hole = false
          state.pending_start = offset
        elsif state.zero_run > 0
          state.pending << ("\x00".b * state.zero_run)
          state.zero_run = 0
        end
        state.pending << data
      end

      # Handles the end of the local source for a scanned sparse upload: a
      # trailing hole is reported and scheduled for a remote resize, and
      # any remaining pending data is queued for sending.
      def finalize_scan(file)
        state = file.sparse
        state.eof = true

        if state.in_hole
          update_progress(:skip, file, state.hole_start, state.pos - state.hole_start)
          state.in_hole = false
          state.resize_to = state.pos
        end

        if state.zero_run > 0
          state.pending << ("\x00".b * state.zero_run)
          state.zero_run = 0
        end

        if state.pending.bytesize > 0
          state.ready << [state.pending_start, state.pending]
          state.pending = +""
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
