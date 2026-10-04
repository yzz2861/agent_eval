# frozen_string_literal: true

require "rack"
require "json"
require "shrine/upload_session"

class Shrine
  module Plugins
    # Documentation can be found on https://shrinerb.com/docs/plugins/upload_session
    module UploadSession
      def self.configure(uploader, **opts)
        uploader.opts[:upload_session] ||= {}
        uploader.opts[:upload_session].merge!(opts)
      end

      module ClassMethods
        # Returns a Rack application that implements the resumable upload
        # session protocol against the given storage:
        #
        #   POST   /                 create a session
        #   PUT    /:session_id      upload a byte range
        #   POST   /:session_id/finalize  finalize and publish
        #   GET    /:session_id      session status with confirmed ranges
        #   DELETE /:session_id      abort the session
        def upload_session_endpoint(storage_key, **)
          Shrine::UploadSessionEndpoint.new(
            shrine_class: self,
            storage_key:  storage_key,
            **opts[:upload_session],
            **,
          )
        end

        # Calls the upload session endpoint passing the request information,
        # and returns the Rack response triple.
        def upload_session_response(storage_key, env, **)
          script_name = env["SCRIPT_NAME"]
          path_info   = env["PATH_INFO"]

          begin
            env["SCRIPT_NAME"] += path_info
            env["PATH_INFO"]    = ""

            upload_session_endpoint(storage_key, **).call(env)
          ensure
            env["SCRIPT_NAME"] = script_name
            env["PATH_INFO"]   = path_info
          end
        end
      end

      module InstanceMethods
        # Creates an upload session on the uploader's storage and returns it.
        def create_upload_session(total_size:, **options)
          storage.create_upload_session(total_size: total_size, **options)
        end

        # Uploads a chunk to the given session on the uploader's storage.
        def put_upload_chunk(session_id, io, **options)
          storage.put_upload_chunk(session_id, io, **options)
        end

        # Returns the current state of the given upload session.
        def get_upload_session(session_id)
          storage.get_upload_session(session_id)
        end
        alias upload_session get_upload_session

        # Finalizes the session and returns the published Shrine::UploadedFile.
        def finalize_upload_session(session_id, **options)
          session = storage.finalize_upload_session(session_id, **options)

          self.class::UploadedFile.new(
            id:       session.uploaded_id,
            storage:  storage_key,
            metadata: session.metadata,
          )
        end

        # Aborts the given upload session.
        def abort_upload_session(session_id)
          storage.abort_upload_session(session_id)
        end
      end
    end

    register_plugin(:upload_session, UploadSession)
  end

  # Rack application implementing the resumable upload session protocol.
  class UploadSessionEndpoint
    CONTENT_TYPE_JSON = "application/json; charset=utf-8"
    CONTENT_TYPE_TEXT = "text/plain"

    def initialize(options)
      options.each do |name, value|
        instance_variable_set("@#{name}", value)
      end
    end

    def call(env)
      request = Rack::Request.new(env)

      status, headers, body = catch(:halt) do
        dispatch(request)
      end

      headers = Rack::Headers[headers] if Rack.release >= "3"
      unless status == 204
        headers["Content-Length"] ||= body.respond_to?(:bytesize) ? body.bytesize.to_s :
                                                                    body.map(&:bytesize).inject(0, :+).to_s
      end

      [status, headers, body]
    end

    def inspect
      "#<#{@shrine_class}::UploadSessionEndpoint(:#{@storage_key})>"
    end
    alias to_s inspect

    private

    def dispatch(request)
      segments = request.path_info.sub(%r{^/}, "").sub(%r{/$}, "").split("/")

      case segments
      in []
        halt_unless!(request.post?, 405, "Method Not Allowed")
        create_session(request)
      in [session_id]
        case request.request_method
        when "PUT"    then put_chunk(session_id, request)
        when "GET"    then get_session(session_id, request)
        when "DELETE" then abort_session(session_id, request)
        else error!(405, "Method Not Allowed")
        end
      in [session_id, "finalize"]
        halt_unless!(request.post?, 405, "Method Not Allowed")
        finalize_session(session_id, request)
      else
        error!(404, "Not Found")
      end
    end

    def create_session(request)
      params = parse_json_request!(request)

      size = params["size"] || params["total_size"]
      error!(400, "total size is required") if size.nil?

      metadata = params["metadata"] || {}
      metadata = metadata.merge("filename" => params["filename"]) if params["filename"]
      metadata = metadata.merge("mime_type" => params["mime_type"]) if params["mime_type"]

      session = with_storage do |storage|
        storage.create_upload_session(
          total_size:         size,
          metadata:           metadata,
          checksum_algorithm: params["checksum_algorithm"],
        )
      end

      [201, { "Content-Type" => CONTENT_TYPE_JSON }, [session_payload(session).to_json]]
    end

    def put_chunk(session_id, request)
      offset = extract_chunk_offset(request)
      error!(400, "chunk offset is required") if offset.nil?

      length = request.env["HTTP_UPLOAD_LENGTH"]&.then { |value| Integer(value) rescue nil }

      session = with_storage do |storage|
        storage.put_upload_chunk(session_id, request.body, offset: offset, length: length)
      end

      [200, { "Content-Type" => CONTENT_TYPE_JSON }, [session_payload(session).to_json]]
    end

    def get_session(session_id, request)
      session = with_storage { |storage| storage.get_upload_session(session_id) }

      [200, { "Content-Type" => CONTENT_TYPE_JSON }, [session_payload(session).to_json]]
    end

    def finalize_session(session_id, request)
      params = request.post? && json_content?(request) ? parse_json_request!(request) : request.params

      uploaded_file = guard_storage_errors do
        uploader.finalize_upload_session(
          session_id,
          checksum:           params["checksum"],
          checksum_algorithm: params["checksum_algorithm"],
          id:                 params["id"],
        )
      end

      body = uploaded_file.to_json
      [200, { "Content-Type" => CONTENT_TYPE_JSON }, [body]]
    end

    def abort_session(session_id, request)
      with_storage { |storage| storage.abort_upload_session(session_id) }

      [204, {}, []]
    end

    def extract_chunk_offset(request)
      header = request.env["HTTP_UPLOAD_OFFSET"] || request.env["HTTP_CONTENT_RANGE"]
      return nil if header.nil? || header.to_s.empty?

      if request.env["HTTP_UPLOAD_OFFSET"]
        Integer(header) rescue nil
      else
        match = header.match(%r{\Abytes (\d+)-\d+/(?:\d+|\*)\z})
        match && Integer(match[1])
      end
    end

    def json_content?(request)
      request.media_type.to_s.include?("application/json")
    end

    def parse_json_request!(request)
      body = request.body.read.to_s
      return {} if body.empty?

      JSON.parse(body)
    rescue JSON::ParserError
      error!(400, "invalid JSON body")
    end

    def session_payload(session)
      {
        "id"         => session.id,
        "total_size" => session.total_size,
        "ranges"     => session.ranges,
        "received"   => session.ranges.sum { |start_offset, end_offset| end_offset - start_offset },
        "finalized"  => session.finalized?,
        "expires_at" => session.expires_at&.iso8601,
      }
    end

    def with_storage
      storage = uploader.storage

      unless storage.respond_to?(:create_upload_session)
        error!(501, "storage #{@storage_key.inspect} does not support upload sessions")
      end

      guard_storage_errors { yield storage }
    end

    def guard_storage_errors
      yield
    rescue Shrine::UploadSessionNotFound   => error
      error!(404, error.message)
    rescue Shrine::UploadChunkConflict     => error
      error!(409, error.message)
    rescue Shrine::UploadChunkOutOfRange   => error
      error!(416, error.message)
    rescue Shrine::UploadSessionIncomplete => error
      error!(409, error.message)
    rescue Shrine::UploadSessionClosed     => error
      error!(409, error.message)
    rescue Shrine::UploadSessionError      => error
      error!(400, error.message)
    rescue ArgumentError                   => error
      error!(400, error.message)
    end

    def halt_unless!(condition, status, message)
      error!(status, message) unless condition
    end

    def error!(status, message)
      throw :halt, [status, { "Content-Type" => CONTENT_TYPE_TEXT }, [message]]
    end

    def uploader
      @shrine_class.new(@storage_key)
    end
  end
end
