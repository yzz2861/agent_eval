# frozen_string_literal: true

class Shrine
  module Plugins
    # Documentation can be found on https://shrinerb.com/docs/plugins/metadata_evidence
    module MetadataEvidence
      # Version of the evidence serialization format. Bumped when the
      # structure of the evidence hash changes in an incompatible way.
      VERSION = 1

      # Metadata fields evidence is recorded for by default.
      DEFAULT_FIELDS = %w[filename size mime_type].freeze

      def self.load_dependencies(uploader, **)
        uploader.plugin :refresh_metadata
        uploader.plugin :validation
      end

      def self.configure(uploader, fields: nil, **)
        uploader.opts[:metadata_evidence] ||= { fields: DEFAULT_FIELDS.dup }
        uploader.opts[:metadata_evidence][:fields] = fields.map(&:to_s) if fields
      end

      module InstanceMethods
        # Extracts metadata along with an evidence record, keeping for each
        # tracked field the value the client declared, the value the server
        # measured, and the value that was adopted into the metadata.
        def extract_metadata(io, **)
          metadata = super

          metadata.merge("evidence" => build_metadata_evidence(io, metadata))
        end

        private

        # Builds a versioned evidence hash for the tracked metadata fields.
        def build_metadata_evidence(io, metadata)
          evidence = { "version" => MetadataEvidence::VERSION }

          opts[:metadata_evidence][:fields].each do |field|
            evidence[field] = {
              "declared" => declared_metadata_value(io, field),
              "probed"   => probed_metadata_value(io, field, metadata),
              "adopted"  => metadata[field],
            }
          end

          evidence
        end

        # Returns the value the client claims for the given metadata field,
        # either through IO attributes (original filename, Content-Type
        # header) or, for uploaded files, through their stored metadata
        # (which might have been submitted as cached attachment data).
        def declared_metadata_value(io, field)
          case field
          when "filename"
            io.original_filename if io.respond_to?(:original_filename)
          when "size"
            io.metadata["size"] if io.is_a?(UploadedFile)
          when "mime_type"
            io.content_type.split(";").first if io.respond_to?(:content_type) && io.content_type
          end
        end

        # Returns the value the server measured for the given metadata
        # field, or nil when the value couldn't be measured from the actual
        # IO content. Never falls back to client-declared values.
        def probed_metadata_value(io, field, metadata)
          case field
          when "size"
            metadata["size"] if probed_size?(io)
          when "mime_type"
            metadata["mime_type"] if probed_mime_type?
          end
        end

        # Whether the size was measured from the IO itself. For uploaded
        # files the size is only trusted once the file has been opened,
        # otherwise it would be read back from its (client-provided)
        # metadata.
        def probed_size?(io)
          if io.is_a?(UploadedFile)
            io.opened?
          else
            io.respond_to?(:size)
          end
        end

        # Whether the MIME type was analyzed from the IO content, which is
        # the case when the determine_mime_type plugin is loaded with a
        # content analyzer (any analyzer other than :content_type).
        def probed_mime_type?
          return false unless self.class.respond_to?(:determine_mime_type)

          self.class.opts[:determine_mime_type][:analyzer] != :content_type
        end
      end

      module FileMethods
        # Returns the evidence hash recorded during metadata extraction, or
        # nil when the file data carries no (supported) evidence, e.g.
        # attachments stored before this plugin was loaded.
        def evidence
          evidence = metadata["evidence"]

          evidence if evidence.is_a?(Hash) && evidence["version"] == MetadataEvidence::VERSION
        end

        # Returns the source the current metadata value was adopted from:
        # :probed (measured by the server), :declared (claimed by the
        # client), or :unknown. Returns nil when no evidence was recorded
        # for the given field. The current metadata value is compared
        # against the recorded evidence, so values changed after extraction
        # are reported as :unknown.
        def metadata_source(field)
          entry = evidence && evidence[field.to_s]
          return unless entry.is_a?(Hash)

          value = metadata[field.to_s]

          if !entry["probed"].nil? && entry["probed"] == value
            :probed
          elsif !entry["declared"].nil? && entry["declared"] == value
            :declared
          else
            :unknown
          end
        end

        # Re-extracts metadata, keeping the previously recorded evidence.
        # Declared values are filled in from the prior evidence when the IO
        # doesn't carry new claims, probed values are always re-measured
        # (never inherited from file data, which may be client-submitted),
        # and adopted values are updated to the refreshed metadata.
        def refresh_metadata!(**)
          prior_evidence = evidence

          super

          fill_declared_evidence(prior_evidence) if prior_evidence
        end

        private

        # Carries over declared values from the prior evidence for fields
        # the refreshed evidence has no declared value for.
        def fill_declared_evidence(prior_evidence)
          current = metadata["evidence"]
          return unless current.is_a?(Hash)

          prior_evidence.each do |field, entry|
            next unless entry.is_a?(Hash) && current[field].is_a?(Hash)
            next if entry["declared"].nil?

            current[field]["declared"] ||= entry["declared"]
          end
        end
      end

      module AttacherMethods
        # Validates that the adopted metadata values for the given fields
        # come from one of the allowed sources (:probed or :declared).
        # Fails closed: when no probed value was recorded, the declared
        # value is not accepted as a substitute, and attachments without
        # evidence (e.g. stored before this plugin was loaded) are
        # rejected as well.
        #
        #     validate_metadata_source :size, :mime_type, sources: [:probed]
        def validate_metadata_source(*fields, sources:, message: nil)
          allowed = Array(sources).map(&:to_sym)

          fields.flatten.each do |field|
            source = file.metadata_source(field.to_s)
            next if allowed.include?(source)

            errors << (message || "metadata #{field} could not be verified from a trusted source (required: #{allowed.join(" or ")}, got: #{source || "none"})")
          end
        end
      end
    end

    register_plugin(:metadata_evidence, MetadataEvidence)
  end
end
