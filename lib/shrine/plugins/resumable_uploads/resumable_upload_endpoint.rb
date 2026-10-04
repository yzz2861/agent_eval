# frozen_string_literal: true

require "rack"
require "json"
require "base64"

class Shrine
  class ResumableUpload
    # Rack application that exposes a {ResumableUpload} service over HTTP.
    # It speaks a small JSON/tus-inspired protocol:
    #
    #   POST   /               create an upload session
    #   PATCH  /:id            submit a byte range (raw request body)
    #   GET    /:id            read session status (confirmed ranges)
    #   HEAD   /:id            session status as response headers
    #   POST   /:id/finalize   verify and publish the completed upload
    #   DELETE /:id            abort an unfinished session
    class ResumableUploadEndpoint
      CONTENT_TYPE_JSON = "application/json; charset=utf-8"
      CONTENT_TYPE_TEXT = "text/plain"

      SESSION_PATH = /\A\/([A-Za-z0-9_-]+)\/?\z/.freeze
      FINALIZE_PATH = /\A\/([A-Za-z0-9_-]+)\/finalize\/?\z/.freeze

      def initialize(service)
        @service = service
      end

      # Accepts a Rack env hash, routes the request and returns a Rack
      # response triple.
      def call(env)
        request = Rack::Request.new(env)

        status, headers, body = catch(:halt) do
          begin
            route(request)
          rescue ResumableUpload::Error => error
            error!(error.status, error.message)
          end
        end

        headers = Rack::Headers[headers] if Rack.release >= "3"
        unless status == 204
          headers["Content-Length"] ||= body.respond_to?(:bytesize) ? body.bytesize.to_s :
                                                                      body.map(&:bytesize).inject(0, :+).to_s
        end

        [status, headers, body]
      end

      def inspect
        "#<#{@service.inspect}::Endpoint>"
      end
      alias to_s inspect

      private

      def route(request)
        path = request.path_info

        if ["", "/"].include?(path)
          return create_session(request) if request.post?

          error!(405, "Method Not Allowed")
        end

        if (match = FINALIZE_PATH.match(path))
          return finalize(request, match[1]) if request.post?

          error!(405, "Method Not Allowed")
        end

        match = SESSION_PATH.match(path)
        error!(404, "Not Found") unless match

        id = match[1]

        case request.request_method
        when "PATCH"  then put_chunk(request, id)
        when "GET"    then session_status(request, id, head: false)
        when "HEAD"   then session_status(request, id, head: true)
        when "DELETE" then abort_session(request, id)
        else               error!(405, "Method Not Allowed")
        end
      end

      # POST /
      def create_session(request)
        params = json_params(request)

        total_size   = params["total_size"]   || params[:total_size]
        checksum     = params["checksum"]     || params[:checksum]
        filename     = params["filename"]     || params[:filename]
        content_type = params["content_type"] || params[:content_type]
        expires_in   = params["expires_in"]   || params[:expires_in]

        total_size ||= request.get_header("HTTP_UPLOAD_LENGTH")
        checksum   ||= parse_upload_checksum(request.get_header("HTTP_UPLOAD_CHECKSUM"))
        filename   ||= parse_upload_metadata(request.get_header("HTTP_UPLOAD_METADATA"))["filename"]

        error!(400, "total_size is required") if total_size.nil? || total_size.to_s.empty?

        total_size = integer_param!("total_size", total_size)
        expires_in = expires_in.nil? ? nil : integer_param!("expires_in", expires_in)

        session = @service.create_session(
          total_size:   total_size,
          checksum:     checksum,
          filename:     filename,
          content_type: content_type,
          expires_in:   expires_in,
        )

        [201, json_headers(session), [session_json(session)]]
      end

      # PATCH /:id
      def put_chunk(request, id)
        chunk = request.body.read.to_s
        start_offset, end_offset = resolve_range(request, chunk)

        session = @service.put_chunk(id, chunk, start_offset: start_offset)

        headers = json_headers(session).merge(
          "Upload-Offset" => end_offset.to_s,
          "Upload-Received-Ranges" => encode_ranges(session.merged_ranges),
        )

        [200, headers, [session_json(session)]]
      end

      # GET/HEAD /:id
      def session_status(request, id, head:)
        session = @service.get_session(id)
        headers = json_headers(session).merge(
          "Upload-Length" => session.total_size.to_s,
          "Upload-Offset" => session.received_size.to_s,
          "Upload-Received-Ranges" => encode_ranges(session.merged_ranges),
        )

        if session.finalized?
          headers["Upload-Finalized"] = "1"
        end

        if head
          [200, headers, []]
        else
          [200, headers, [session_json(session)]]
        end
      end

      # POST /:id/finalize
      def finalize(request, id)
        params = json_params(request)

        location = params["location"] || params[:location]
        metadata = params["metadata"] || params[:metadata]

        uploaded_file = @service.finalize(id, location: location, metadata: metadata)

        body = uploaded_file.to_json
        [200, { "Content-Type" => CONTENT_TYPE_JSON }, [body]]
      end

      # DELETE /:id
      def abort_session(request, id)
        @service.abort(id)
        [204, {}, []]
      end

      # Extracts the absolute start/end offsets for the request body.
      # Accepts either a `Content-Range: bytes START-END/TOTAL` header or a
      # tus-style `Upload-Offset: START` header.
      def resolve_range(request, chunk)
        content_range = request.get_header("HTTP_CONTENT_RANGE")

        if content_range
          match = /\Abytes (\d+)-(\d+)\/(?:\d+|\*)\z/.match(content_range.strip)
          error!(400, "invalid Content-Range header") unless match

          start_offset = Integer(match[1])
          end_offset   = Integer(match[2]) + 1

          unless end_offset - start_offset == chunk.bytesize
            error!(400, "Content-Range does not match chunk length")
          end

          return [start_offset, end_offset]
        end

        upload_offset = request.get_header("HTTP_UPLOAD_OFFSET")
        error!(400, "Upload-Offset or Content-Range header is required") if upload_offset.nil?

        start_offset = Integer(upload_offset)
        [start_offset, start_offset + chunk.bytesize]
      rescue ArgumentError
        error!(400, "invalid byte offset")
      end

      # tus: `Upload-Checksum: sha256 <base64-encoded-hex-or-raw-digest>`.
      def parse_upload_checksum(header)
        return nil if header.nil? || header.to_s.empty?

        algorithm, encoded = header.split(/\s+/, 2)
        error!(400, "invalid Upload-Checksum header") if encoded.nil?

        decoded = Base64.decode64(encoded)
        digest = decoded.match?(/\A[0-9a-fA-F]+\z/) ? decoded : decoded.unpack1("H*")
        "#{algorithm.downcase}=#{digest.downcase}"
      end

      # tus: `Upload-Metadata: key value,key2 value2` with base64 values.
      def parse_upload_metadata(header)
        result = {}
        return result if header.nil? || header.to_s.empty?

        header.split(",").each do |pair|
          key, encoded = pair.strip.split(/\s+/, 2)
          next unless key

          result[key] = encoded ? Base64.decode64(encoded) : ""
        end
        result
      end

      def json_params(request)
        return {} if request.body.nil?

        body = request.body.read
        return {} if body.nil? || body.empty?

        JSON.parse(body)
      rescue JSON::ParserError
        {}
      end

      def integer_param!(name, value)
        Integer(value)
      rescue ArgumentError, TypeError
        error!(400, "#{name} must be an integer")
      end

      def session_json(session)
        JSON.generate(session.to_h)
      end

      def json_headers(session)
        {
          "Content-Type" => CONTENT_TYPE_JSON,
          "Upload-Length" => session.total_size.to_s,
          "Upload-Received-Ranges" => encode_ranges(session.merged_ranges),
        }
      end

      # `"0 99,100 249"` — pairs of space-separated half-open offsets.
      def encode_ranges(ranges)
        ranges.map { |start_offset, end_offset| "#{start_offset} #{end_offset}" }.join(",")
      end

      def error!(status, message)
        throw :halt, [status, { "Content-Type" => CONTENT_TYPE_TEXT }, [message]]
      end
    end
  end
end
