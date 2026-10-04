# frozen_string_literal: true

module StorageMigration
  # Immutable description of a storage migration.
  #
  # A plan pins down everything that must stay fixed for the whole run:
  #
  # * the identity of the source storage (only objects in this storage are
  #   migrated),
  # * the target storage and the location objects are copied to,
  # * the metadata fields that must match between source and copy before
  #   an attachment is switched over,
  # * the manifest file used to record progress and resume interrupted
  #   migrations.
  class Plan
    DEFAULT_VERIFY_METADATA = %w[size mime_type filename].freeze

    attr_reader :source_storage, :target_storage, :verify_metadata, :manifest_path

    def initialize(source_storage:, target_storage:, target_location: nil,
                   verify_metadata: DEFAULT_VERIFY_METADATA, manifest_path:)
      @source_storage  = source_storage.to_sym
      @target_storage  = target_storage.to_sym
      @target_location = target_location
      @verify_metadata = verify_metadata.map(&:to_s).freeze
      @manifest_path   = manifest_path

      validate!
      freeze
    end

    # Deterministic object id in the target storage for a given source id.
    def target_id_for(source_id)
      case @target_location
      when nil    then source_id
      when Proc   then @target_location.call(source_id)
      when String then "#{@target_location}/#{source_id}"
      else
        raise ArgumentError, "unsupported target_location: #{@target_location.inspect}"
      end
    end

    private

    def validate!
      if source_storage == target_storage
        raise ArgumentError, "source and target storage must be different"
      end
    end
  end
end
