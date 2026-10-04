# frozen_string_literal: true

class Shrine
  module Plugins
    # Documentation can be found on https://shrinerb.com/docs/plugins/content_addressable
    module ContentAddressable
      def self.configure(uploader, **opts)
        uploader.opts[:content_addressable] ||= { digest: :sha256, prefix: nil }
        uploader.opts[:content_addressable].merge!(opts)
      end

      module InstanceMethods
        # Generates a location based on the hash of the file content, so that
        # files with the same content share the same location. The hash is
        # calculated on the server from the actual file content.
        def generate_location(io, metadata: {}, **)
          content_addressable_location(io, metadata: metadata)
        end

        def content_addressable_location(io, metadata: {})
          extension   = ".#{io.extension}" if io.is_a?(UploadedFile) && io.extension
          extension ||= File.extname(metadata["filename"].to_s).downcase

          prefix = opts[:content_addressable][:prefix]
          digest = content_addressable_digest(io)

          [*prefix, "#{digest}#{extension}"].join("/")
        end

        private

        # Hashes the actual file content, rewinding the IO afterwards.
        def content_addressable_digest(io)
          require "digest"
          digest = Digest.const_get(opts[:content_addressable][:digest].to_s.upcase).new

          digest.update(io.read(16*1024, buffer ||= String.new)) until io.eof?
          io.rewind

          digest.hexdigest
        end
      end
    end

    register_plugin(:content_addressable, ContentAddressable)
  end
end
