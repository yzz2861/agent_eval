# frozen_string_literal: true

require "securerandom"
require "digest"
require "json"
require "time"

class Shrine
  module Plugins
    # Documentation can be found on https://shrinerb.com/docs/plugins/resumable_uploads
    module ResumableUploads
      def self.configure(uploader, **opts)
        uploader.opts[:resumable_uploads] ||= {}
        uploader.opts[:resumable_uploads].merge!(opts)
      end

      module ClassMethods
        # Returns a resumable upload service which creates upload sessions,
        # accepts byte-range chunks and finalizes completed uploads.
        #
        # The `storage_key` needs to be one of the registered Shrine
        # storages. Additional options can be given to override the options
        # given on plugin initialization.
        def resumable_upload(storage_key, **overrides)
          if overrides.empty?
            @resumable_uploads ||= {}
            @resumable_uploads[storage_key.to_sym] ||= Shrine::ResumableUpload.new(
              shrine_class: self,
              storage_key:  storage_key,
              **opts[:resumable_uploads],
            )
          else
            Shrine::ResumableUpload.new(
              shrine_class: self,
              storage_key:  storage_key,
              **opts[:resumable_uploads],
              **overrides,
            )
          end
        end

        # Returns a Rack application (object that responds to `#call`)
        # which exposes the resumable upload service over HTTP:
        #
        #   POST   /            create session
        #   PATCH  /:id         append a byte range
        #   HEAD   /:id         retrieve received ranges
        #   POST   /:id/finalize  publish the completed upload
        def resumable_upload_endpoint(storage_key, **)
          resumable_upload(storage_key, **).endpoint
        end
      end
    end

    register_plugin(:resumable_uploads, ResumableUploads)
  end
end

require_relative "resumable_uploads/session"
require_relative "resumable_uploads/session_store"
require_relative "resumable_uploads/resumable_upload"
require_relative "resumable_uploads/resumable_upload_endpoint"
