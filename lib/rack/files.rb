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
  # By default, file metadata and response contents are loaded lazily from
  # +path+. To serve one file version during an atomic replacement, either pass
  # an already-open +File+ to #serving, or pass <tt>{pin: true}</tt> as the
  # fourth ::new option. File metadata, byte ranges and response body then use
  # the same file descriptor. For complete responses, #to_path refers to that
  # descriptor when the platform supports it; otherwise it returns nil so
  # middleware cannot reopen the replaced path.

  class Files
    ALLOWED_VERBS = %w[GET HEAD OPTIONS]
    ALLOW_HEADER = ALLOWED_VERBS.join(', ')
    MULTIPART_BOUNDARY = 'AaB03x'

    attr_reader :root

    class Callable
      def initialize(files)
        @files = files
      end

      def call(env)
        @files.get env
      end
    end

    def initialize(root, headers = {}, default_mime = 'text/plain', options = {})
      @root = (::File.expand_path(root) if root)
      @headers = headers
      @default_mime = default_mime
      @pin = options[:pin]
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

      available = begin
        ::File.file?(path) && ::File.readable?(path)
      rescue SystemCallError
        # Not sure in what conditions this exception can occur, but this
        # is a safe way to handle such an error.
        # :nocov:
        false
        # :nocov:
      end

      if available
        serving(request, path)
      else
        fail(404, "File not found: #{path_info}")
      end
    end

    def serving(request, path, pin: @pin)
      file = path if path.respond_to?(:stat)
      path = file.path if file

      if request.options?
        file.close if file && !file.closed?
        return [200, { 'allow' => ALLOW_HEADER, CONTENT_LENGTH => '0' }, []]
      end

      file ||= ::File.open(path, 'rb') if pin
      body_owns_file = !request.head?

      begin
        last_modified = (file ? file.stat.mtime : ::File.mtime(path)).httpdate
        return [304, {}, []] if request.get_header('HTTP_IF_MODIFIED_SINCE') == last_modified

        headers = { "last-modified" => last_modified }
        mime_type = mime_type path, @default_mime
        headers[CONTENT_TYPE] = mime_type if mime_type

        assign_headers(headers, request)

        status = 200
        size = filesize(file || path)

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
          response_body = new_iterator(file || path, ranges, { mime_type: mime_type, size: size })
          size = response_body.bytesize
        end

        headers[CONTENT_LENGTH] = size.to_s

        if request.head?
          response_body = []
        elsif !partial_content
          response_body = new_iterator(file || path, ranges, { mime_type: mime_type, size: size }, complete: !partial_content)
        end

        [status, headers, response_body]
      ensure
        if file && !file.closed? && !(body_owns_file && response_body)
          file.close
        end
      end
    end

    def assign_headers(headers, request)
      headers.merge!(@headers) if @headers
    end

    def new_iterator(source, ranges, options, complete: false)
      if source.respond_to?(:stat)
        PinnedIterator.new(source, ranges, options)
      elsif !complete
        BaseIterator.new(source, ranges, options)
      else
        Iterator.new(source, ranges, options)
      end
    end

    class BaseIterator
      attr_reader :path, :ranges, :options

      def initialize(source, ranges, options)
        if source.respond_to?(:read)
          @file = source
        else
          @path = source
        end
        @ranges = ranges
        @options = options
      end

      def each
        if @file
          begin
            each_range_set(@file) { |part| yield part }
          ensure
            close
          end
        else
          ::File.open(path, "rb") do |file|
            each_range_set(file) { |part| yield part }
          end
        end
      end

      def close
        @file.close if @file && !@file.closed?
      end

      def closed?
        @file.nil? || @file.closed?
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

      def each_range_set(file)
        ranges.each do |range|
          break if @file&.closed?
          yield multipart_heading(range) if multipart?

          each_range_part(file, range) { |part| yield part }
        end

        yield "\r\n--#{MULTIPART_BOUNDARY}--\r\n" if multipart? && !@file&.closed?
      end

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
        return if @file&.closed?

        file.seek(range.begin)
        remaining_len = range.end - range.begin + 1
        while remaining_len > 0
          break if @file&.closed?
          part = file.read([8192, remaining_len].min)
          break unless part
          remaining_len -= part.length

          yield part
        end
      end
    end

    class Iterator < BaseIterator
      alias :to_path :path
    end

    class PinnedIterator < BaseIterator
      FILE_DESCRIPTOR_PATH = "/dev/fd"

      # A file descriptor path preserves the opened inode on POSIX systems.
      # Range responses cannot use a sendfile shortcut because the descriptor
      # path represents the entire file, so nil is returned to force the body
      # enumerator and retain the computed range guarantee.
      def to_path
        return nil if @file.closed?
        return nil unless complete_file?
        return nil unless ::File.directory?(FILE_DESCRIPTOR_PATH)

        "#{FILE_DESCRIPTOR_PATH}/#{@file.to_i}"
      end

      private

      def complete_file?
        ranges.size == 1 &&
          ranges.first.begin.zero? &&
          ranges.first.end == options[:size] - 1
      end
    end

    private

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

    def filesize(file)
      #   We check via File::size? whether this file provides size info
      #   via stat (e.g. /proc files often don't), otherwise we have to
      #   figure it out by reading the whole file into memory.
      if file.respond_to?(:stat)
        size = file.stat.size
        return size unless size.zero?

        file.rewind
        begin
          file.read.bytesize
        ensure
          file.rewind
        end
      else
        ::File.size?(file) || ::File.read(file).bytesize
      end
    end
  end
end
