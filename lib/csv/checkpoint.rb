# frozen_string_literal: true

require "digest"

class CSV
  # The error thrown when a checkpoint cannot be created or used to
  # resume parsing. See CSV#checkpoint and CSV#resume.
  class CheckpointError < RuntimeError
  end

  #
  # A CSV::Checkpoint captures the position and parser state needed to
  # resume parsing a seekable CSV input at the start of the next
  # undelivered record. It is designed for batch import workflows:
  # process a batch of records, persist the checkpoint, and -- even
  # after a restart -- reopen the input and continue with the record
  # that follows the last fully delivered one.
  #
  # A checkpoint is only valid at a record boundary, that is, after a
  # complete record has been delivered to the caller. It never relies
  # on the raw IO position alone, because the parser may have buffered
  # (read ahead) data beyond the last delivered record.
  #
  # A checkpoint carries:
  #
  # [position]
  #   The byte offset in the input at which the next record starts.
  # [lineno]
  #   The number of rows parsed so far, so CSV#lineno keeps counting
  #   after a resume.
  # [headers]
  #   The headers already read from the input, when headers are used,
  #   so they are neither re-read nor re-emitted after a resume.
  # [options]
  #   A fingerprint of the resolved parse options (including the
  #   auto-detected row separator). CSV#resume refuses a checkpoint
  #   created with different options.
  # [input]
  #   An identity fingerprint of the input (path, size, modification
  #   time and a content digest, when available). CSV#resume refuses
  #   a checkpoint created for a different or modified input.
  #
  # Resuming only manages the read position of the CSV input. It does
  # not provide exactly-once semantics for side effects performed by
  # the consumer (such as database writes): if a failure happens after
  # a record was delivered but before the checkpoint was persisted,
  # that record will be delivered again after the resume.
  #
  # Use CSV#checkpoint to capture a checkpoint, #to_h (or #dump) to
  # persist it, and CSV#resume to continue parsing later:
  #
  #   CSV.open(path, headers: true) do |csv|
  #     csv.each_slice(100) do |batch|
  #       import(batch) # e.g. insert into a database
  #       File.write("checkpoint", csv.checkpoint.dump)
  #     end
  #   end
  #
  #   # after a restart:
  #   CSV.open(path, headers: true) do |csv|
  #     csv.resume(CSV::Checkpoint.load(File.read("checkpoint")))
  #     csv.each {|row| ... } # continues with the next record
  #   end
  #
  class Checkpoint
    VERSION = 1

    # Number of leading input bytes included in the content digest used
    # to identify the input.
    DIGEST_PREFIX_SIZE = 4096

    attr_reader :position, :lineno, :headers, :options, :input

    def initialize(position:, lineno:, headers:, options:, input:)
      @version = VERSION
      @position = position
      @lineno = lineno
      @headers = headers
      @options = options
      @input = input
    end

    # Returns a plain Hash representation of this checkpoint, suitable
    # for serialization with Marshal, JSON, YAML, and so on.
    def to_h
      {
        "version" => @version,
        "position" => @position,
        "lineno" => @lineno,
        "headers" => @headers,
        "options" => @options,
        "input" => @input,
      }
    end

    # Rebuilds a checkpoint from a Hash created by #to_h. Raises
    # CSV::CheckpointError if the checkpoint format is not supported.
    def self.from_h(hash)
      hash = hash.transform_keys(&:to_s)
      version = hash["version"]
      unless version == VERSION
        message = "unsupported checkpoint version: #{version.inspect}"
        raise CheckpointError, message
      end
      new(position: hash["position"],
          lineno: hash["lineno"],
          headers: hash["headers"],
          options: hash["options"] || {},
          input: hash["input"] || {})
    end

    # Serializes this checkpoint to a String. See also #to_h.
    def dump
      Marshal.dump(to_h)
    end

    # Rebuilds a checkpoint from a String created by #dump.
    def self.load(string)
      from_h(Marshal.load(string))
    end

    # Normalizes a parse option fingerprint so that it only contains
    # values that survive serialization and can be compared across
    # processes.
    def self.normalize_options(options)
      normalized = {}
      options.each do |key, value|
        normalized[key.to_s] = normalize_option_value(value)
      end
      normalized
    end

    def self.normalize_option_value(value)
      case value
      when nil, true, false, Integer, Float, String
        value
      when Array
        value.collect {|element| normalize_option_value(element)}
      else
        value.inspect
      end
    end
    private_class_method :normalize_option_value

    # Returns true if this checkpoint was created with the same parse
    # options as the given (normalized) fingerprint.
    def options_match?(normalized_options)
      @options == normalized_options
    end

    # Captures an identity fingerprint for the given input. The
    # fingerprint uses whatever the input offers: path, size,
    # modification time, and a digest of the leading bytes for
    # seekable inputs.
    def self.capture_input(io)
      identity = {}
      identity["path"] = io.path.to_s if io.respond_to?(:path) && io.path
      if io.respond_to?(:stat)
        begin
          stat = io.stat
          identity["size"] = stat.size
          identity["mtime"] = stat.mtime.to_f
        rescue IOError, SystemCallError
          # not a real file; fall back to the content digest only
        end
      end
      if io.is_a?(StringIO)
        string = io.string
        identity["size"] = string.bytesize
        identity["digest"] = digest(string.byteslice(0, DIGEST_PREFIX_SIZE) || "")
      elsif io.respond_to?(:pos) && io.respond_to?(:seek)
        begin
          position = io.pos
          begin
            io.seek(0)
            prefix = io.read(DIGEST_PREFIX_SIZE) || ""
          ensure
            io.seek(position)
          end
          identity["digest"] = digest(prefix)
        rescue IOError, SystemCallError
          # not seekable; CSV#checkpoint rejects such inputs anyway
        end
      end
      identity
    end

    # Returns true if the given input looks identical to the input this
    # checkpoint was created from.
    def input_matches?(io)
      current = self.class.capture_input(io)
      @input.all? do |key, value|
        current[key] == value
      end
    end

    def self.digest(data)
      Digest::SHA256.hexdigest(data)
    end
    private_class_method :digest
  end
end
