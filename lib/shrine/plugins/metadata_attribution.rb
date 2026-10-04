# frozen_string_literal: true

class Shrine
  module Plugins
    # The +metadata_attribution+ plugin records where each metadata value came
    # from. For every recorded metadata field it keeps three pieces of
    # information:
    #
    #   * the value *declared* by the client (e.g. an upload form),
    #   * the value *measured* on the server side (from file content),
    #   * the value that was actually *adopted* as the metadata value.
    #
    # Evidence is embedded into the serialized attachment data using a
    # versioned format. Attachments saved before the plugin was loaded (which
    # contain no evidence) can still be read.
    module MetadataAttribution
      # Metadata key / data key under which evidence is stored.
      EVIDENCE_KEY = "metadata_evidence".freeze

      # Current version of the serialized evidence format.
      VERSION = 1

      # Metadata fields recorded by default.
      DEFAULT_FIELDS = %w[filename size mime_type].freeze

      def self.configure(uploader, fields: nil, **)
        uploader.opts[:metadata_attribution] ||= { fields: DEFAULT_FIELDS.dup, trusted: nil }
        uploader.opts[:metadata_attribution][:fields] = Array(fields).map(&:to_s) if fields
      end

      def self.load_dependencies(uploader, **)
        uploader.plugin :refresh_metadata
        uploader.plugin :validation
      end

      module ClassMethods
        # Metadata fields for which attribution evidence is recorded.
        def metadata_attribution_fields
          opts[:metadata_attribution][:fields]
        end
      end

      module InstanceMethods
        private

        # Collects metadata together with attribution observations. When
        # +preserve_evidence+ is true (metadata refresh) previous observations
        # are carried over so refreshing never destroys prior evidence. When
        # +server_observed+ is true the re-extraction happens on behalf of the
        # server, so carried client claims are unflagged and new observations
        # are marked as trusted.
        def get_metadata(io, metadata: nil, preserve_evidence: false, server_observed: false, **options)
          @__metadata_attribution = nil

          if io.is_a?(UploadedFile) && metadata != true
            result = io.metadata.dup
            # Promoting/copying a file keeps its already recorded evidence
            # verbatim (no new observation is made here).
            existing_evidence = result[EVIDENCE_KEY]
            result[EVIDENCE_KEY] = existing_evidence if existing_evidence.is_a?(Hash)
          elsif metadata == false
            result = {}
          else
            # Only an explicit metadata refresh preserves prior evidence.
            @__metadata_attribution =
              if preserve_evidence
                _copy_metadata_observations(io, unflag_client: server_observed)
              end
            result = extract_metadata(io, **options)
            _mark_server_observations if server_observed
          end

          if metadata.is_a?(Hash)
            declared = metadata.transform_keys(&:to_s)
            declared.delete(EVIDENCE_KEY)
            result = result.merge(declared)
            _record_declared_metadata(declared)
          end

          if @__metadata_attribution
            evidence = _build_metadata_evidence(@__metadata_attribution)
            result[EVIDENCE_KEY] = evidence
            _apply_adopted_metadata(result, evidence)
          end
          result
        end

        # Filename coming from #original_filename is client controlled; a name
        # derived from a server-side path is treated as measured.
        def extract_filename(io)
          value = super
          _tag_metadata_value("filename", value, io.respond_to?(:original_filename) ? :declared : :measured)
          value
        end

        # Size is read from the IO object itself, so it is measured.
        def extract_size(io)
          value = super
          _tag_metadata_value("size", value, :measured)
          value
        end

        # Without the determine_mime_type plugin the MIME type is copied from
        # the client-controlled Content-Type header, so it is declared. The
        # determine_mime_type plugin re-tags the value as measured.
        def extract_mime_type(io)
          value = super
          _tag_metadata_value("mime_type", value, :declared)
          value
        end

        # Appends an observation for the given field.
        def _tag_metadata_value(field, value, source)
          return unless _metadata_attribution_field?(field)

          @__metadata_attribution ||= {}
          @__metadata_attribution[field] ||= []
          @__metadata_attribution[field] << { "source" => source.to_s, "value" => value }
        end

        def _record_declared_metadata(declared)
          return unless @__metadata_attribution

          declared.each do |field, value|
            _tag_metadata_value(field, value, :declared) if _metadata_attribution_field?(field)
          end
        end

        # Observations produced during a server-side re-evaluation are trusted
        # and never downgraded by the cached-data trust boundary.
        def _mark_server_observations
          @__metadata_attribution&.each_value do |observations|
            observations.each do |observation|
              observation.delete("client_supplied")
              observation["server_observed"] = true
            end
          end
        end

        def _copy_metadata_observations(io, unflag_client: false)
          return nil unless io.is_a?(UploadedFile)

          evidence = io.metadata[EVIDENCE_KEY]
          return nil unless evidence.is_a?(Hash)

          (evidence["fields"] || {}).each_with_object({}) do |(field, entry), copied|
            next unless entry.is_a?(Hash) && entry["observations"].is_a?(Array)

            copied[field] = entry["observations"].map do |observation|
              observation.dup.tap do |copied_observation|
                # A server-side refresh produces new, trusted provenance, so
                # carried observations are no longer considered untrusted.
                copied_observation.delete("client_supplied") if unflag_client
              end
            end
          end
        end

        # Builds versioned evidence and picks the adopted value. The newest
        # measured value wins; a declared value is never used as a substitute
        # for a missing measured value.
        def _build_metadata_evidence(observations)
          fields = observations.each_with_object({}) do |(field, entries), result|
            measured = entries.reverse.find { |entry| entry["source"] == "measured" }
            declared = entries.reverse.find { |entry| entry["source"] == "declared" }

            if measured
              adopted_source, adopted_value = "measured", measured["value"]
            elsif declared
              adopted_source, adopted_value = "declared", declared["value"]
            else
              latest = entries.last
              adopted_source, adopted_value = latest["source"], latest["value"]
            end

            result[field] = {
              "declared"     => declared&.dig("value"),
              "measured"     => measured&.dig("value"),
              "adopted"      => adopted_value,
              "source"       => adopted_source,
              "observations" => entries,
            }
          end

          { "version" => VERSION, "fields" => fields }
        end

        def _metadata_attribution_field?(field)
          self.class.metadata_attribution_fields.include?(field.to_s)
        end

        # Makes the adopted evidence value authoritative in the top-level
        # metadata hash, so a client declaration can never mask a measured
        # value (and vice versa).
        def _apply_adopted_metadata(result, evidence)
          (evidence["fields"] || {}).each do |field, entry|
            result[field] = entry["adopted"]
          end
        end

      end

      module FileMethods
        # Evidence hash, or nil when no evidence was recorded.
        def metadata_evidence
          metadata[EVIDENCE_KEY]
        end

        # Evidence recorded for a single field.
        def metadata_attribution(field)
          metadata.dig(EVIDENCE_KEY, "fields", field.to_s)
        end

        # Client-declared value for the field.
        def declared_metadata(field)
          metadata_attribution(field)&.dig("declared")
        end

        # Server-measured value for the field.
        def measured_metadata(field)
          metadata_attribution(field)&.dig("measured")
        end

        # Source of the adopted value (:measured / :declared), or nil.
        def metadata_source(field)
          metadata_attribution(field)&.dig("source")&.to_sym
        end

        # Whether the adopted value originates from one of the given sources.
        def metadata_from?(*sources, field:)
          source = metadata_source(field)
          !source.nil? && sources.map(&:to_sym).include?(source)
        end

        # Refreshing metadata keeps prior evidence and records new observations.
        # Refreshing is a server-side operation, so new observations are
        # trusted by default (+server_observed: true+). The flag exists so the
        # restore_cached_data integration can express the same intent
        # explicitly regardless of plugin load order.
        def refresh_metadata!(replace: false, server_observed: true, **options)
          return open { refresh_metadata!(replace:, server_observed:, **options) } unless opened?

          refreshed_metadata =
            uploader.send(:get_metadata, self, metadata: true,
                          preserve_evidence: true, server_observed:, **options)
          evidence = refreshed_metadata[EVIDENCE_KEY]

          @metadata = replace ? refreshed_metadata : @metadata.merge(refreshed_metadata)
          @metadata[EVIDENCE_KEY] = evidence
        end

        # Marks observations carried by client-supplied cached data. Every
        # observation flagged this way is treated as a declaration, no matter
        # what source it claims, because a client cannot prove server-side
        # measurement. Idempotent: legitimate observations appended later by a
        # server refresh are not flagged and therefore stay trusted.
        def mark_client_metadata_evidence!
          evidence = metadata[EVIDENCE_KEY]
          return unless evidence.is_a?(Hash)

          (evidence["fields"] || {}).each do |field, entry|
            next unless entry.is_a?(Hash)

            (entry["observations"] || []).each do |observation|
              observation["client_supplied"] = true unless observation["server_observed"]
            end
          end
        end

        # Downgrades flagged observations and recomputes declared/measured/
        # adopted values from the remaining observations.
        def distrust_client_metadata_evidence!
          evidence = metadata[EVIDENCE_KEY]
          return unless evidence.is_a?(Hash)

          (evidence["fields"] || {}).each do |field, entry|
            next unless entry.is_a?(Hash)

            observations = entry["observations"] || []

            observations.each do |observation|
              observation["source"] = "declared" if observation["client_supplied"] && !observation["server_observed"]
            end

            measured = observations.reverse.find { |o| o["source"] == "measured" }
            declared = observations.reverse.find { |o| o["source"] == "declared" }

            entry["measured"] = measured&.dig("value")
            entry["declared"] = declared&.dig("value")

            if measured
              entry["source"], entry["adopted"] = "measured", measured["value"]
            elsif declared
              entry["source"], entry["adopted"] = "declared", declared["value"]
            end

            # Keep the top-level metadata consistent with the adopted value.
            metadata[field] = entry["adopted"]
          end
        end

      end

      module AttacherClassMethods
        # Configures which metadata sources are trusted.
        #
        #   Attacher.metadata_trusted_sources :measured
        #   Attacher.metadata_trusted_sources size: :measured
        def metadata_trusted_sources(*sources, **field_sources)
          config = shrine_class.opts[:metadata_attribution]

          field_sources = field_sources.transform_keys(&:to_s)
                               .transform_values { |value| Array(value).map(&:to_s) }

          config[:trusted] = { global: sources.map(&:to_s), fields: field_sources }
        end
      end

      module AttacherMethods
        # Returns the configured trusted sources, optionally for a field.
        def metadata_trusted_sources(field = nil)
          trusted = shrine_class.opts[:metadata_attribution][:trusted]
          return nil unless trusted

          (field && trusted[:fields][field.to_s]) || trusted[:global]
        end

        # Whether the adopted value of the field comes from a trusted source.
        # Without a configured policy every source is trusted.
        def metadata_source_trusted?(field)
          trusted = metadata_trusted_sources(field)
          return true if trusted.nil? || trusted.empty?

          source = file&.metadata_source(field)
          !source.nil? && trusted.include?(source.to_s)
        end

        # Adds a validation error unless the adopted value of every field (or
        # the given fields) originates from a trusted source. A missing
        # measured value does not fall back to a declared one.
        def validate_metadata_source(*fields, message: nil)
          if fields.empty? && file&.metadata_evidence
            fields = file.metadata_evidence["fields"].keys
          end
          fields = Array(fields).map(&:to_s)

          fields.map do |field|
            trusted = metadata_trusted_sources(field)
            source  = file.metadata_source(field)
            valid   = trusted && source && trusted.include?(source.to_s)
            valid || add_metadata_source_error(field, trusted, message)
          end.all?
        end

        private

        def add_metadata_source_error(field, trusted, message)
          errors << (
            message ||
            "metadata source for #{field} must be one of: #{Array(trusted).join(", ")}, " \
            "but was #{file.metadata_source(field).inspect}"
          )
          false
        end

        # Attachment data arriving through the cache entry point is controlled
        # by the client, so its claimed evidence cannot be trusted.
        def cached(value, **)
          cached_file = super
          _mark_cached_metadata_evidence(cached_file)
          _distrust_cached_metadata_evidence(cached_file)
          cached_file
        end

        def _mark_cached_metadata_evidence(cached_file)
          case cached_file
          when Shrine::UploadedFile then cached_file.mark_client_metadata_evidence!
          when Hash then cached_file.each_value { |file| _mark_cached_metadata_evidence(file) }
          when Array then cached_file.each { |file| _mark_cached_metadata_evidence(file) }
          end
        end

        def _distrust_cached_metadata_evidence(cached_file)
          case cached_file
          when Shrine::UploadedFile then cached_file.distrust_client_metadata_evidence!
          when Hash then cached_file.each_value { |file| _distrust_cached_metadata_evidence(file) }
          when Array then cached_file.each { |file| _distrust_cached_metadata_evidence(file) }
          end
        end
      end
    end

    register_plugin(:metadata_attribution, MetadataAttribution)
  end
end
