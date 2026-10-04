# frozen_string_literal: true

class Shrine
  # Prepares a group of attachments before publishing all references through
  # one persistence callback. File storage is not transactional, so the
  # prepare, commit, and cleanup phases are kept separate and explicit.
  class AttacherGroup
    class ValidationFailed < Shrine::Error
      attr_reader :errors

      def initialize(errors)
        @errors = errors
        super("attachments failed validation: #{errors.inspect}")
      end
    end

    class CommitFailed < Shrine::Error
      def initialize(error)
        super("attachment group persistence failed: #{error.message}")
      end
    end

    Entry = Struct.new(:attacher, :io, :options, :name, :explicit, keyword_init: true)

    def self.submit(*args, **options, &persist)
      new(*args, **options, &persist).submit
    end

    def initialize(*args, &persist)
      @entries   = []
      @persist   = persist
      @prepared  = false
      @committed = false
      @old_data  = {}
      @new_files = {}
      @changed   = []

      args.each { |arg| add(arg) }
    end

    def add(specifier, io = nil, **options)
      case specifier
      when AttacherGroup
        @entries.concat(specifier.entries)
      when Attacher
        add_attacher(specifier, io, **options)
      when Array
        add_array(specifier, **options)
      when Hash
        specifier.each { |name, item| add(item, name: name) }
      else
        fail ArgumentError, "expected an attacher, array, or hash, got #{specifier.inspect}"
      end

      self
    end

    # Uploads all new objects to permanent storage and runs every attacher's
    # validation. If anything fails, the attachers are restored to their old
    # references and objects uploaded during this attempt are deleted.
    def prepare
      return self if @prepared

      begin
        @entries.each { |entry| prepare_entry(entry) }
      rescue StandardError
        abort
        raise
      end

      errors = validation_errors
      if errors.any?
        abort
        raise ValidationFailed.new(errors)
      end

      @prepared = true
      self
    end

    # Publishes the complete set of new references through one callback. A
    # callback failure restores old references and deletes new objects.
    def commit(&persist)
      prepare unless @prepared
      return self if @committed

      persist ||= @persist
      fail ArgumentError, "a persistence callback is required" unless persist

      begin
        result = call_persist(persist, references, @entries)
        raise CommitFailed.new(StandardError.new("persistence callback returned false")) if result == false
      rescue StandardError => error
        abort
        raise error.is_a?(CommitFailed) ? error : CommitFailed.new(error)
      end

      @committed = true
      self
    end

    # Deletes old objects after the business commit has succeeded. A failure
    # here is allowed to propagate; calling #cleanup again retries it and
    # cannot undo the successful commit.
    def cleanup
      return self unless @committed

      @changed.each(&:finalize)
      @old_data.clear
      @new_files.clear
      @changed.clear
      self
    end

    def submit
      prepare
      commit
      cleanup
      self
    end

    def abort
      delete_errors = []

      @entries.each do |entry|
        next unless @old_data.key?(entry)

        new_files = @new_files[entry] || files(entry.attacher.file)
        restore(entry.attacher, @old_data[entry])
        new_files.each do |file|
          file.delete
        rescue StandardError
          delete_errors << $!
        end
      end

      if delete_errors.empty?
        @old_data.clear
        @new_files.clear
        @changed.clear
      end

      @prepared = false

      raise delete_errors.first unless delete_errors.empty?

      self
    end

    def references
      prepare unless @prepared

      @entries.each_with_object({}) do |entry, references|
        key = entry.name
        key ||= entry.attacher.name if entry.attacher.respond_to?(:name)
        key ||= entry.attacher.attribute if entry.attacher.respond_to?(:attribute)
        key ||= @entries.index(entry)

        references[key] = reference_for(entry.attacher)
      end
    end

    def prepared?
      @prepared
    end

    def committed?
      @committed
    end

    protected

    attr_reader :entries

    private

    def add_array(array, **options)
      if array.length == 2 && array.first.is_a?(Attacher)
        add_attacher_pair(array.first, array.last, **options)
      else
        array.each { |item| add(item, **options) }
      end
    end

    def add_attacher(attacher, io, name: nil, explicit: !io.nil?, **options)
      add_entry(attacher, io, name:, explicit:, **options)
    end

    def add_attacher_pair(attacher, io, name: nil, **options)
      add_entry(attacher, io, name:, explicit: true, **options)
    end

    def add_entry(attacher, io, name:, explicit:, **options)
      @entries << Entry.new(
        attacher: attacher,
        io: io,
        name: name,
        options: options,
        explicit: explicit,
      )
    end

    def prepare_entry(entry)
      attacher = entry.attacher
      old_data = attacher.changed? ? previous_data(attacher) : attacher.data
      @old_data[entry] = old_data
      current_file = attacher.file

      if entry.explicit
        attacher.attach(entry.io, **upload_options(entry.options))
      elsif attacher.changed?
        attacher.promote_cached(**upload_options(entry.options))
      end

      return unless entry.explicit || attacher.file != current_file

      validate(attacher, entry.options)

      @new_files[entry] = files(attacher.file)
      @changed << attacher
    end

    def validate(attacher, options)
      return unless attacher.respond_to?(:errors)
      return if options[:validate] == false

      attacher.validate
    end

    def upload_options(options)
      options.except(:validate)
    end

    def validation_errors
      @entries.filter_map do |entry|
        next unless entry.attacher.respond_to?(:errors)

        errors = entry.attacher.errors
        errors unless errors.empty?
      end
    end

    def previous_data(attacher)
      previous_file = attacher.previous_file
      data_of(previous_file)
    end

    def data_of(object)
      case object
      when Hash
        object.each_with_object({}) do |(key, value), result|
          result[key.to_s] = data_of(value)
        end
      when Array
        object.map { |value| data_of(value) }
      when nil
        nil
      else
        object.data
      end
    end

    def call_persist(persist, references, entries)
      case persist.arity
      when 0 then persist.call
      when 1 then persist.call(references)
      else persist.call(references, entries)
      end
    end

    def reference_for(attacher)
      if attacher.respond_to?(:column_data)
        attacher.column_data
      else
        attacher.data
      end
    end

    def restore(attacher, data)
      attacher.set(data.nil? ? nil : attacher.uploaded_file(data))
    end

    def files(object)
      case object
      when Hash
        object.values.flat_map { |value| files(value) }
      when Array
        object.flat_map { |value| files(value) }
      when nil
        []
      else
        [object]
      end
    end

  end
end
