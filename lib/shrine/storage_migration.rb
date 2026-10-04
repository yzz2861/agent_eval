# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "tempfile"
require "shrine/plugins/atomic_helpers"

class Shrine
  class StorageMigration
    CHECKSUM_ALGORITHM = "sha256"
    FAILURE_STATUSES = %w[copy_failed verify_failed switch_failed].freeze

    TERMINAL_STATUSES = %w[
      switched
      metadata_mismatch
      source_changed
    ].freeze

    class Plan
      attr_reader :items

      def self.load(path)
        new(JSON.parse(File.read(path))["items"])
      end

      def self.build(entries)
        new(entries.map do |entry|
          file = entry[:file] || entry.fetch(:attacher).file
          fail ArgumentError, "source file is required" unless file

          target_storage = entry[:target_storage] || entry.dig(:target, :storage)
          target_id      = entry[:target_id]      || entry.dig(:target, :id)      || file.id

          fail ArgumentError, "target storage is required" unless target_storage

          {
            id:       entry.fetch(:id),
            source:   { storage: file.storage_key, id: file.id },
            target:   { storage: target_storage, id: target_id },
            checksum: StorageMigration.checksum(file),
            metadata: entry[:metadata] || file.metadata,
          }
        end)
      end

      def initialize(items = [])
        @items = items.map { |item| Item.new(item) }
      end

      def find(id)
        items.find { |item| item.id == id }
      end

      def each(&block)
        items.each(&block)
      end

      def to_h
        { "items" => items.map(&:to_h) }
      end

      def save(path)
        StorageMigration.atomic_write(path, JSON.pretty_generate(to_h))
      end

      class Item
        attr_reader :id, :source, :target, :checksum, :metadata

        def initialize(attributes)
          data = StorageMigration.stringify_keys(attributes)

          @id       = data.fetch("id")
          @source   = normalize_location(data.fetch("source"))
          @target   = normalize_location(data.fetch("target"))
          @checksum = data.fetch("checksum")
          @metadata = data.fetch("metadata")

          validate!
        end

        def source_data
          location_data(source)
        end

        def target_data
          location_data(target)
        end

        def to_h
          {
            "id"       => id,
            "source"   => source,
            "target"   => target,
            "checksum" => checksum,
            "metadata" => metadata,
          }
        end

        private

        def location_data(location)
          {
            "id"       => location["id"],
            "storage"  => location["storage"],
            "metadata" => metadata,
          }
        end

        def normalize_location(value)
          data = StorageMigration.stringify_keys(value)
          {
            "storage" => data.fetch("storage").to_s,
            "id"      => data.fetch("id"),
          }
        end

        def validate!
          fail ArgumentError, "migration item id is required" if id.nil? || id.to_s.empty?
          fail ArgumentError, "source and target storage must differ" if source["storage"] == target["storage"]
          unless checksum.match?(/\A[a-f0-9]{64}\z/)
            fail ArgumentError, "checksum must be a SHA256 hex digest"
          end
          fail ArgumentError, "metadata must be a Hash" unless metadata.is_a?(Hash)
        end
      end
    end

    class ResultLog
      attr_reader :path, :results

      def self.load(path)
        data = File.exist?(path) ? JSON.parse(File.read(path)) : {}
        new(path: path, results: data["items"] || {})
      end

      def initialize(path:, results: {})
        @path    = path
        @results = StorageMigration.stringify_keys(results)
      end

      def [](id)
        results[id.to_s]
      end

      def record(item, status:, stage:, **attributes)
        previous = results[item.id] || {}
        failure  = FAILURE_STATUSES.include?(status)

        result = {
          "id"       => item.id,
          "status"   => status,
          "stage"    => stage,
          "source"   => item.source,
          "target"   => item.target,
          "checksum" => item.checksum,
          "metadata" => item.metadata.dup,
          "attempts" => previous.fetch("attempts", 0) + (failure ? 1 : 0),
        }.merge(StorageMigration.stringify_keys(attributes))

        results[item.id] = result
        save
        result
      end

      def copied?(item)
        result = results[item.id]
        return false unless result
        return false unless %w[copied switch_failed attachment_changed].include?(result["status"])

        result["source"]   == item.source &&
          result["target"]   == item.target &&
          result["checksum"] == item.checksum &&
          result.dig("target_file", "id") == item.target["id"] &&
          result.dig("target_file", "storage") == item.target["storage"]
      end

      def terminal?(item)
        result = results[item.id]
        result && TERMINAL_STATUSES.include?(result["status"]) &&
          result["source"] == item.source &&
          result["target"] == item.target
      end

      def to_h
        { "items" => results }
      end

      def save
        StorageMigration.atomic_write(path, JSON.pretty_generate(to_h))
      end
    end

    def self.checksum(uploaded_file)
      digest = Digest(CHECKSUM_ALGORITHM.upcase).new
      uploaded_file.open do |io|
        while (chunk = io.read(1024 * 1024))
          digest.update(chunk)
        end
      end
      digest.hexdigest
    end

    def self.atomic_write(path, contents)
      FileUtils.mkdir_p(File.dirname(path))

      Tempfile.create([File.basename(path), ".tmp"], File.dirname(path)) do |file|
        file.write(contents)
        file.flush
        file.fsync
        FileUtils.mv(file.path, path)
      end
    end

    def self.stringify_keys(value)
      case value
      when Hash
        value.each_with_object({}) do |(key, nested_value), result|
          result[key.to_s] = stringify_keys(nested_value)
        end
      when Array
        value.map { |item| stringify_keys(item) }
      else
        value
      end
    end

    def initialize(find_attacher:, reload: nil, persist: nil, switch: nil)
      @find_attacher = find_attacher
      @reload        = reload
      @persist       = persist
      @switch        = switch

      if (reload.nil? && persist) || (persist.nil? && reload)
        fail ArgumentError, "reload and persist must be provided together"
      end
    end

    def run(plan, result_log)
      plan.items.map { |item| run_item(item, result_log) }
    end

    private

    def run_item(item, result_log)
      return result_log[item.id] if result_log.terminal?(item)

      attacher = @find_attacher.call(item)
      source   = attacher.uploaded_file(item.source_data)

      unless current_attachment?(attacher, source)
        return result_log.record(item, status: "attachment_changed", stage: "validate",
                                 actual: current_identity(attacher))
      end

      unless attacher.file.metadata == item.metadata
        return result_log.record(item, status: "metadata_mismatch", stage: "validate",
                                 actual_metadata: attacher.file.metadata)
      end

      copied_file = copy(item, attacher, source, result_log)
      return copied_file unless copied_file.is_a?(Shrine::UploadedFile)

      switch_attachment(item, attacher, source, copied_file, result_log)
    end

    def copy(item, attacher, source, result_log)
      if result_log.copied?(item)
        target = attacher.uploaded_file(item.target_data)
        return target if verified_target?(target, item)
      end

      unless source.exists?
        return result_log.record(item, status: "source_missing", stage: "copy")
      end

      begin
        source_checksum = self.class.checksum(source)
      rescue StandardError => error
        return failure(result_log, item, "source_failed", "copy", error)
      end

      unless source_checksum == item.checksum
        return result_log.record(item, status: "source_changed", stage: "copy",
                                 actual_checksum: source_checksum)
      end

      existing_target = attacher.uploaded_file(item.target_data)
      return existing_target if existing_target.exists? && verified_target?(existing_target, item)

      target_file =
        begin
          attacher.upload(source, item.target["storage"].to_sym,
                          location: item.target["id"], metadata: item.metadata,
                          action: :storage_migration)
        rescue StandardError => error
          return failure(result_log, item, "copy_failed", "copy", error)
        end

      begin
        verify_target!(target_file, item)
      rescue StandardError => error
        return failure(result_log, item, "verify_failed", "copy", error)
      end

      result_log.record(item, status: "copied", stage: "copy", target_file: target_file.data)
      target_file
    end

    def switch_attachment(item, attacher, source, target_file, result_log)
      perform_switch(item, attacher, source, target_file)
      result_log.record(item, status: "switched", stage: "switch", target_file: target_file.data)
    rescue Shrine::AttachmentChanged
      result_log.record(item, status: "attachment_changed", stage: "switch",
                       actual: current_identity(attacher), target_file: target_file.data)
    rescue StandardError => error
      result_log.record(item, status: "switch_failed", stage: "switch",
                       error: { "class" => error.class.name, "message" => error.message },
                       target_file: target_file.data)
    end

    def perform_switch(item, attacher, source, target_file)
      if @switch
        @switch.call(item: item, attacher: attacher, source_file: source, target_file: target_file)
      elsif @reload && @persist
        @reload.call(attacher, item) do |reloaded_attacher|
          unless reloaded_attacher.file == source
            fail Shrine::AttachmentChanged, "attachment has changed"
          end
          reloaded_attacher.set(target_file)
          @persist.call(reloaded_attacher, item)
        end
      elsif attacher.respond_to?(:atomic_persist)
        attacher.set(target_file)
        attacher.atomic_persist(source)
      else
        fail ArgumentError,
             "provide reload and persist callbacks, a switch callback, or a persistence plugin"
      end
    end

    def current_attachment?(attacher, source)
      attacher.file &&
        attacher.file.id == source.id &&
        attacher.file.storage_key == source.storage_key
    end

    def current_identity(attacher)
      attacher.file && { "id" => attacher.file.id, "storage" => attacher.file.storage_key.to_s }
    end

    def verified_target?(target, item)
      verify_target!(target, item)
      true
    rescue StandardError
      false
    end

    def verify_target!(target, item)
      fail Shrine::Error, "target storage differs" unless target.storage_key == item.target["storage"].to_sym
      fail Shrine::Error, "target id differs" unless target.id == item.target["id"]
      fail Shrine::Error, "target metadata differs" unless target.metadata == item.metadata
      fail Shrine::Error, "target was not copied yet" unless target.exists?
      fail Shrine::Error, "target checksum differs" unless self.class.checksum(target) == item.checksum
    end

    def failure(result_log, item, status, stage, error)
      result_log.record(
        item,
        status: status,
        stage: stage,
        error: { "class" => error.class.name, "message" => error.message },
      )
    end
  end
end
