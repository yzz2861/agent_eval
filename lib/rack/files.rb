# frozen_string_literal: true

require 'time'

require_relative 'constants'
require_relative 'head'
require_relative 'utils'
require_relative 'request'
require_relative 'mime'

module Rack
  # Rack::Files serves files below the +root+ directory given, according to the
  # path info of the Rack request.
  # e.g. when Rack::Files.new("/etc") is used, you can access 'passwd' file
  # as http://localhost:9292/passwd
  #
  # Handlers can detect if bodies are a Rack::Files, and use mechanisms
  # like sendfile on the +path+.
  #
  # Be aware that just like the default behavior of most webservers, Rack::Files
  # will follow symbolic links encountered under the root. If a symlink points to
  # a location outside of the root, that target will still be served as part of
  # the response.
  #
  # == Atomic deployments and pinned file versions
  #
  # Static files are commonly published by writing a temporary file and then
  # atomically replacing the destination (for example with File.rename). By
  # default, Rack::Files derives the response metadata from the path while
  # building the response, but re-opens that same path later when the response
  # body is iterated. If the file is replaced in between, the response headers
  # (last-modified, content-length, content-range, ...) can describe the old
  # file while the body streams the new file.
  #
  # Pass +pinned = true+ as the fourth constructor argument (or call
  # #serving_pinned_file with an already opened
  # file) to open the file exactly once and derive every response header from
  # the open file's own stat information. Conditional requests, HEAD, single and
  # multipart Range requests and ordinary GET then all describe and transmit
  # the same version of the file, even if the path is replaced or unlinked
  # afterwards. The open file handle is always released when the body is closed,
  # iterated fully, iterated only partially, or when iteration raises.
  #
  # Interaction with Rack::Sendfile: a pinned response body intentionally does
  # not expose #to_path. The sendfile shortcuts hand a path back to the web
  # server, which would re-open the path from disk and silently lose the
  # version guarantee (the web server could send the replacement file). Pinning
  # and kernel sendfile offloading are therefore mutually exclusive; when
  # pinning is enabled the body is streamed from the pinned file descriptor
  # instead.

  class Files
    ALLOWED_VERBS = %w[GET HEAD OPTIONS]
    ALLOW_HEADER = ALLOWED_VERBS.join(', ')
    MULTIPART_BOUNDARY = 'AaB03x'

    attr_reader :root

    # Whether response bodies pin the open file so an atomic replacement of the
    # served path cannot change what is transmitted (see the class docs).
    attr_reader :pinned

    class Callable
      def initialize(files)
        @files = files
      end

      def call(env)
        @files.get env
      end
    end

    def initialize(root, headers = {}, default_mime = 'text/plain', pinned = false)
      @root = (::File.expand_path(root) if root)
      @headers = headers
      @default_mime = default_mime
      @pinned = pinned
      @head = Rack::Head.new(Callable.new(self))
    end

    def call(env)
      # HEAD requests drop the response body, including 4xx error messages.
      @head.call env
    end

    def get(env)
      request = Rack::Request.new env
      unless ALLOWED_VERBS.include? request.request_method
        return fail(405, "Method Not Allowed", { 'allow' => ALLOW_HEADER })
      end

      path_info = Utils.unescape_path request.path_info
      return fail(400, "Bad Request") unless Utils.valid_path?(path_info)

      clean_path_info = Utils.clean_path_info(path_info)
      path = ::File.join(@root, clean_path_info)

      if @pinned
        # Open once and keep the descriptor, so every header and body byte
        # refers to the same file version even if +path+ is replaced later.
        file = begin
          ::File.open(path, "rb")
        rescue SystemCallError
          nil
        end

        if file
          begin
            stat = file.stat
            servable = stat.file? && stat.readable?
          rescue SystemCallError
            # :nocov:
            servable = false
            # :nocov:
          end

          if servable
            begin
              response = serving_with_file(request, path, file)
              # Close unless the body took ownership of the descriptor:
              file.close unless response[2].is_a?(PinnedIterator)
              return response
            rescue
              file.close unless file.closed?
              raise
            end
          end
        end

        file&.close
        return fail(404, "File not found: #{path_info}")
      end

      if file_available?(path)
        serving(request, path)
      else
        fail(404, "File not found: #{path_info}")
      end
    end

    # Serve a request using an already opened file. The caller transfers
    # ownership of +file+ to this method: the returned response body closes it
    # when it is iterated or closed by the handler (Rack::Head closes it for
    # HEAD responses). When the response itself carries no file-backed body
    # (OPTIONS, 304, 416 or HEAD), the file is closed immediately here.
    def serving_pinned_file(request, file)
      response = serving_with_file(request, file.path, file)
      file.close unless response[2].is_a?(PinnedIterator)
      response
    end

    def serving(request, path)
      serving_with_file(request, path, nil)
    end

    def assign_headers(headers, request)
      headers.merge!(@headers) if @headers
    end

    # Shared byte-range iteration logic. #each must guarantee the underlying
    # IO is released whether iteration completes, stops early or raises; the
    # concrete classes decide how the IO is opened and closed.
    module IteratorBehavior
      attr_reader :ranges, :options

      def initialize(ranges, options)
        @ranges = ranges
        @options = options
      end

      def bytesize
        size = ranges.inject(0) do |sum, range|
          sum += multipart_heading(range).bytesize if multipart?
          sum += range.size
        end
        size += "\r\n--#{MULTIPART_BOUNDARY}--\r\n".bytesize if multipart?
        size
      end

      private

      def multipart?
        ranges.size > 1
      end

      def multipart_heading(range)
<<-EOF
\r
--#{MULTIPART_BOUNDARY}\r
content-type: #{options[:mime_type]}\r
content-range: bytes #{range.begin}-#{range.end}/#{options[:size]}\r
\r
EOF
      end

      def each_range_part(file, range)
        file.seek(range.begin)
        remaining_len = range.end - range.begin + 1
        while remaining_len > 0
          part = file.read([8192, remaining_len].min)
          break unless part
          remaining_len -= part.length

          yield part
        end
      end

      def stream(file)
        ranges.each do |range|
          yield multipart_heading(range) if multipart?

          each_range_part(file, range) do |part|
            yield part
          end
        end

        yield "\r\n--#{MULTIPART_BOUNDARY}--\r\n" if multipart?
      end
    end

    # Path based body: the file is opened for each iteration and is guaranteed
    # to be closed again by the block.
    class BaseIterator
      include IteratorBehavior

      attr_reader :path

      def initialize(path, ranges, options)
        @path = path
        super(ranges, options)
      end

      def each
        ::File.open(path, "rb") do |file|
          stream(file) { |part| yield part }
        end
      end

      def close; end
    end

    class Iterator < BaseIterator
      alias :to_path :path
    end

    # Body backed by an open file descriptor. The descriptor is owned by the
    # response body and is closed exactly once: after a full or partial
    # iteration, when iteration raises, or when #close is called (for example
    # by Rack::Head for HEAD requests or by middleware discarding the body).
    # #to_path is deliberately not defined so Rack::Sendfile cannot re-open
    # the path and defeat the version pin.
    class PinnedIterator
      include IteratorBehavior

      def initialize(file, ranges, options)
        @file = file
        @closed = false
        super(ranges, options)
      end

      def each
        raise IOError, "closed stream" if @closed
        begin
          stream(@file) { |part| yield part }
        ensure
          close
        end
      end

      def close
        return if @closed
        @closed = true
        @file.close
      end

      def closed?
        @closed
      end
    end

    private

    def serving_with_file(request, path, file)
      if request.options?
        return [200, { 'allow' => ALLOW_HEADER, CONTENT_LENGTH => '0' }, []]
      end

      if file
        stat = file.stat
        last_modified = stat.mtime.httpdate
        size = stat.size
      else
        last_modified = ::File.mtime(path).httpdate
      end
      if request.get_header('HTTP_IF_MODIFIED_SINCE') == last_modified
        return [304, {}, []]
      end

      headers = { "last-modified" => last_modified }
      mime_type = mime_type(file ? file.path : path, @default_mime)
      headers[CONTENT_TYPE] = mime_type if mime_type

      assign_headers(headers, request)

      status = 200
      size = filesize(file || path) unless file

      ranges = Rack::Utils.get_byte_ranges(request.get_header('HTTP_RANGE'), size)
      if ranges.nil?
        # No ranges:
        ranges = [0..size - 1]
      elsif ranges.empty?
        # Unsatisfiable. Return error, and file size:
        response = fail(416, "Byte range unsatisfiable")
        response[1]["content-range"] = "bytes */#{size}"
        return response
      else
        # Partial content
        partial_content = true

        if ranges.size == 1
          range = ranges[0]
          headers["content-range"] = "bytes #{range.begin}-#{range.end}/#{size}"
        else
          headers[CONTENT_TYPE] = "multipart/byteranges; boundary=#{MULTIPART_BOUNDARY}"
        end

        status = 206
        body = new_iterator(path, file, ranges, mime_type, size, false)
        size = body.bytesize
      end

      headers[CONTENT_LENGTH] = size.to_s

      if request.head?
        body = []
      elsif !partial_content
        body = new_iterator(path, file, ranges, mime_type, size, true)
      end

      [status, headers, body]
    end

    def new_iterator(path, file, ranges, mime_type, size, full_file)
      options = { mime_type: mime_type, size: size }
      if file
        PinnedIterator.new(file, ranges, options)
      elsif full_file
        Iterator.new(path, ranges, options)
      else
        BaseIterator.new(path, ranges, options)
      end
    end

    def fail(status, body, headers = {})
      body += "\n"

      [
        status,
        {
          CONTENT_TYPE   => "text/plain",
          CONTENT_LENGTH => body.bytesize.to_s,
          "x-cascade" => "pass"
        }.merge!(headers),
        [body]
      ]
    end

    # The MIME type for the contents of the file located at @path
    def mime_type(path, default_mime)
      Mime.mime_type(::File.extname(path), default_mime)
    end

    def filesize(path)
      #   We check via File::size? whether this file provides size info
      #   via stat (e.g. /proc files often don't), otherwise we have to
      #   figure it out by reading the whole file into memory.
      if path.respond_to?(:stat)
        size = begin
          path.stat.size
        rescue SystemCallError
          # :nocov:
          nil
          # :nocov:
        end
        return size if size

        contents = path.read
        path.rewind
        contents.bytesize
      else
        ::File.size?(path) || ::File.read(path).bytesize
      end
    end

    def file_available?(path)
      begin
        ::File.file?(path) && ::File.readable?(path)
      rescue SystemCallError
        # Not sure in what conditions this exception can occur, but this
        # is a safe way to handle such an error.
        # :nocov:
        false
        # :nocov:
      end
    end
  end
end
