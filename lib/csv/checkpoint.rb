# frozen_string_literal: true

class CSV
  # Raised when a checkpoint cannot be used to resume parsing, for example
  # when the input or the parsing options have changed since the checkpoint
  # was taken.
  class InvalidCheckpointError < StandardError
  end

  #
  # A CSV::Checkpoint marks a position in a CSV input: the byte offset at
  # which the next record to parse starts. A checkpoint is created via
  # CSV#checkpoint and is only available after a complete record has been
  # delivered, so it never points into the middle of a record (not even
  # into the middle of a multi-line quoted field).
  #
  # Besides the offset, a checkpoint carries everything needed to resume
  # parsing later on:
  #
  # - The headers, if they were already read from the input.
  # - The parsing configuration, including the resolved row separator
  #   (important when +row_sep+ is +:auto+).
  # - The identity of the input (file stat or content digest), so a stale
  #   checkpoint is rejected instead of silently misparsing a changed input.
  #
  # A checkpoint can be serialized with #dump and restored with
  # CSV::Checkpoint.load, then passed as the +resume+ option to CSV.new:
  #
  #   # First run: import in batches, persist a checkpoint per batch.
  #   CSV.open(path, headers: true) do |csv|
  #     csv.each do |row|
  #       import(row)
  #       File.write("checkpoint", csv.checkpoint.dump)
  #     end
  #   end
  #
  #   # After a restart: continue with the next unparsed record.
  #   checkpoint = CSV::Checkpoint.load(File.read("checkpoint"))
  #   CSV.open(path, headers: true, resume: checkpoint) do |csv|
  #     csv.each do |row|
  #       import(row)
  #       File.write("checkpoint", csv.checkpoint.dump)
  #     end
  #   end
  #
  # Note that resuming only manages the read position within the CSV input.
  # It does not provide exactly-once semantics for writes done by the
  # consumer (such as database inserts): records imported after the last
  # persisted checkpoint may be delivered again after a restart.
  #
  class Checkpoint
    # The serialization format version of #dump/#to_h.
    FORMAT_VERSION = 1

    # Byte offset in the input where the next record starts.
    attr_reader :offset
    # The CSV#lineno value to continue with.
    attr_reader :lineno
    # Headers already read from the input, or +nil+ if headers aren't used.
    attr_reader :headers
    # The resolved row separator (never +:auto+).
    attr_reader :row_separator
    # The name of the encoding the input is parsed in.
    attr_reader :encoding
    # Fingerprint of the parsing options the checkpoint was taken with.
    attr_reader :options
    # Identity of the input the checkpoint was taken from.
    attr_reader :input

    def initialize(offset:,
                   lineno:,
                   headers:,
                   row_separator:,
                   encoding:,
                   options:,
                   input:)
      @offset = offset
      @lineno = lineno
      @headers = headers
      @row_separator = row_separator
      @encoding = encoding
      @options = options
      @input = input
    end

    # Returns the checkpoint as a plain Hash of simple values.
    def to_h
      {
        "version" => FORMAT_VERSION,
        "offset" => @offset,
        "lineno" => @lineno,
        "headers" => @headers,
        "row_separator" => @row_separator,
        "encoding" => @encoding,
        "options" => @options,
        "input" => @input,
      }
    end

    # Returns a serialized String that can be persisted and later restored
    # with CSV::Checkpoint.load.
    def dump
      Marshal.dump(to_h)
    end

    class << self
      # Restores a checkpoint from a CSV::Checkpoint, a Hash as returned by
      # #to_h, or a String as returned by #dump. Raises
      # CSV::InvalidCheckpointError if the payload isn't a supported
      # checkpoint.
      def load(payload)
        case payload
        when Checkpoint
          payload
        when Hash
          from_hash(payload)
        when String
          hash =
            begin
              Marshal.load(payload)
            rescue TypeError, ArgumentError
              raise InvalidCheckpointError, "malformed checkpoint data"
            end
          from_hash(hash)
        else
          message = "checkpoint must be a CSV::Checkpoint, Hash or String: "
          message += payload.inspect
          raise InvalidCheckpointError, message
        end
      end

      # Normalizes a parsing option value so that option hashes can be
      # compared (and serialized) across processes.
      def normalize_option_value(value)
        case value
        when nil, true, false, Numeric
          value
        when String
          value
        when Symbol
          value.to_s
        when Regexp
          value.source
        when Encoding
          value.name
        when Array
          value.collect {|element| normalize_option_value(element)}
        when Hash
          normalized = {}
          value.each do |key, element|
            normalized[key.to_s] = normalize_option_value(element)
          end
          normalized
        else
          value.class.name
        end
      end

      # Normalizes a hash of parsing options; see normalize_option_value.
      def normalize_options(options)
        normalized = {}
        options.each do |key, value|
          normalized[key] = normalize_option_value(value)
        end
        normalized
      end

      private
      def from_hash(hash)
        version = hash["version"]
        unless version == FORMAT_VERSION
          message = "unsupported checkpoint format version: #{version.inspect}"
          raise InvalidCheckpointError, message
        end
        new(offset: hash["offset"],
            lineno: hash["lineno"],
            headers: hash["headers"],
            row_separator: hash["row_separator"],
            encoding: hash["encoding"],
            options: hash["options"],
            input: hash["input"])
      end
    end
  end
end
