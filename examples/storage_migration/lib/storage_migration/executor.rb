# frozen_string_literal: true

require "digest"
require "json"

module StorageMigration
  # Raised when an object copied to the target storage does not match its
  # source (checksum or metadata mismatch).
  class VerificationError < StandardError; end

  # Executes a StorageMigration::Plan against a list of records.
  #
  # The migration is split into three explicit phases:
  #
  #   copy_phase    - copies each source object to the target storage and
  #                   verifies content and metadata before recording it.
  #   switch_phase  - points the attachment column at the verified copy,
  #                   but only if the original reference is unchanged.
  #   cleanup_phase - deletes source objects of switched records. This is
  #                   deliberately a separate, explicit phase.
  #
  # Every step is appended to the plan's manifest, so an interrupted run
  # resumes where it left off and never re-uploads an object that was
  # already copied and verified.
  class Executor
    CHUNK_SIZE = 16 * 1024

    attr_reader :plan, :uploader, :name, :manifest

    def initialize(plan, uploader:, name: :image)
      @plan     = plan
      @uploader = uploader
      @name     = name.to_sym
      @manifest = Manifest.new(plan.manifest_path)

      validate_storages!
    end

    # Copies and verifies everything, then switches attachments. Source
    # cleanup is *not* part of a run; call #cleanup_phase explicitly.
    def run(records)
      copy_phase(records)
      switch_phase(records)
    end

    def copy_phase(records)
      each_source_file(records) do |_record, key, source_file|
        sha256 = sha256(source_file)
        entry  = manifest[key]

        if entry && %w[copied switched cleaned].include?(entry["status"]) &&
           entry["source_id"] == source_file.id && entry["sha256"] == sha256
          next # this exact source object was already copied and verified
        end

        target_id = plan.target_id_for(source_file.id)

        begin
          target_file = upload(source_file, target_id)
          verify!(source_file, target_file)
        rescue StandardError => error
          manifest.record(key, "failed",
            source_id: source_file.id,
            target_id: target_id,
            error:     "#{error.class}: #{error.message}")
          next
        end

        manifest.record(key, "copied",
          source_id: source_file.id,
          sha256:    sha256,
          target_id: target_file.id,
          metadata:  source_file.metadata)
      end
    end

    def switch_phase(records)
      records.each do |record|
        key   = key_for(record)
        entry = manifest[key]
        next unless entry && entry["status"] == "copied"

        current = current_reference(record)
        next unless current

        if current["id"] == entry["source_id"] && current["storage"] == plan.source_storage.to_s
          write_column(record,
            "id"       => entry["target_id"],
            "storage"  => plan.target_storage.to_s,
            "metadata" => entry["metadata"])
          manifest.record(key, "switched",
            source_id: entry["source_id"],
            target_id: entry["target_id"])
        else
          manifest.record(key, "skipped",
            source_id:  entry["source_id"],
            reason:     "attachment_changed",
            current_id: current["id"])
        end
      end
    end

    # Deletes source objects of records that were switched to the target
    # storage. Safe to run repeatedly; a source object is only deleted while
    # the record still points at the migrated copy.
    def cleanup_phase(records)
      records.each do |record|
        key   = key_for(record)
        entry = manifest[key]
        next unless entry && entry["status"] == "switched"

        current = current_reference(record)
        unless current && current["id"] == entry["target_id"] &&
               current["storage"] == plan.target_storage.to_s
          next # record no longer points at the migrated object; leave the source alone
        end

        source_storage.delete(entry["source_id"])
        manifest.record(key, "cleaned",
          source_id: entry["source_id"],
          target_id: entry["target_id"])
      end
    end

    private

    def validate_storages!
      [plan.source_storage, plan.target_storage].each do |storage|
        unless uploader.storages.key?(storage)
          raise ArgumentError, "storage #{storage.inspect} is not registered on #{uploader}"
        end
      end
    end

    def each_source_file(records)
      records.each do |record|
        data = column_data(record)
        next unless data
        next unless data["storage"] == plan.source_storage.to_s

        yield record, key_for(record), uploader.uploaded_file(data)
      end
    end

    def key_for(record)
      "#{record.class.name}##{record.id}"
    end

    def current_reference(record)
      column_data(record)
    end

    def column_data(record)
      record.reload if record.respond_to?(:reload)

      case raw = record.public_send(:"#{name}_data")
      when nil    then nil
      when String then JSON.parse(raw)
      when Hash   then raw
      else raise ArgumentError, "unexpected #{name}_data: #{raw.inspect}"
      end
    end

    def write_column(record, data)
      record.public_send(:"#{name}_data=", JSON.generate(data))
      record.save if record.respond_to?(:save)
    end

    def upload(source_file, target_id)
      target_uploader = uploader.new(plan.target_storage)
      target_uploader.upload(source_file, location: target_id)
    end

    def verify!(source_file, target_file)
      unless sha256(source_file) == sha256(target_file)
        raise VerificationError, "checksum mismatch for #{source_file.id}"
      end

      plan.verify_metadata.each do |field|
        source_value = source_file.metadata[field]
        target_value = target_file.metadata[field]
        unless source_value.to_s == target_value.to_s
          raise VerificationError,
            "metadata #{field.inspect} mismatch for #{source_file.id}: " +            "#{source_value.inspect} != #{target_value.inspect}"
        end
      end
    end

    def sha256(uploaded_file)
      digest = Digest::SHA256.new
      uploaded_file.open
      while (chunk = uploaded_file.read(CHUNK_SIZE))
        digest.update(chunk)
      end
      digest.hexdigest
    ensure
      uploaded_file.close
    end

    def source_storage
      uploader.storages.fetch(plan.source_storage)
    end
  end
end
