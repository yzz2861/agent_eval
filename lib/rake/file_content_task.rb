# frozen_string_literal: true
require "digest"
require "fileutils"
require "json"
require "pathname"
require "securerandom"
require "set"

require_relative "file_task"

module Rake

  # A file task whose freshness is determined by a content signature rather
  # than modification times.
  class FileContentTask < FileTask
    CONTENT_SIGNATURE_VERSION = 1
    DEFAULT_SIGNATURE_DIR = File.join(".rake", "file-content-signatures")
    UNSET = Object.new.freeze
    private_constant :UNSET

    class << self
      # Declare a content-based file task. In addition to the usual target,
      # prerequisites and action block, these options participate in the
      # signature:
      #
      # +inputs+:: input file paths
      # +env+:: names of environment variables
      # +params+:: arbitrary JSON-compatible parameters
      # +action_version+:: version changed manually when an action changes
      def define_task(*args, &block)
        options = args.last.is_a?(Hash) ? args.pop : {}
        signature_options = extract_signature_options(options)
        args << options unless options.empty?

        task = super(*args, &block)
        task.configure_content_signature(**signature_options)
        task
      end

      # Compute the signature for one configured task.
      def signature(configuration)
        signature_object(configuration).to_s
      end

      # Build the structured fingerprint represented by one signature.
      def signature_fingerprint(configuration)
        signature_object(configuration).to_h
      end

      private

      def signature_object(configuration)
        FileContentSignature.new(configuration)
      end

      def extract_signature_options(options)
        signature_options = {}
        if options.key?(:signature_dir)
          signature_options[:signature_dir] =
            options.delete(:signature_dir) || DEFAULT_SIGNATURE_DIR
        end
        [:inputs, :env, :params, :action_version].each do |key|
          signature_options[key] = options.delete(key) if options.key?(key)
        end
        signature_options
      end
    end

    attr_reader :content_inputs, :content_env, :content_params, :action_version,
                :signature_dir

    def initialize(task_name, app)
      super
      @content_inputs = []
      @content_env = []
      @content_params = nil
      @content_params_set = false
      @action_version = nil
      @signature_dir = DEFAULT_SIGNATURE_DIR
    end

    # Configure values included in the content signature. Options supplied
    # later replace earlier values; omitted options are preserved.
    def configure_content_signature(inputs: UNSET, env: UNSET, params: UNSET,
                                    action_version: UNSET,
                                    signature_dir: UNSET)
      unless inputs.equal?(UNSET)
        @content_inputs = Array(inputs).map { |path|
          Rake.from_pathname(path).to_s
        }
      end
      @content_env = Array(env).map(&:to_s) unless env.equal?(UNSET)
      unless params.equal?(UNSET)
        @content_params = params
        @content_params_set = true
      end
      unless action_version.equal?(UNSET)
        @action_version = action_version
      end
      unless signature_dir.equal?(UNSET)
        @signature_dir = Rake.from_pathname(signature_dir).to_s
      end

      unless @action_version.is_a?(Numeric)
        raise ArgumentError, "file_content requires a numeric action_version"
      end

      self
    end

    # Rebuild when the target, declared inputs, environment, parameters, or
    # action version no longer match the signature recorded by a successful
    # build. Modification times are intentionally ignored.
    def needed?
      return true if application.options.build_all
      current_signature != recorded_signature
    end

    def execute(args=nil)
      return super if application.options.dryrun

      super
      verify_output
      record_signature
    end

    def current_signature
      self.class.signature(content_signature_configuration)
    end

    def current_signature_fingerprint
      self.class.signature_fingerprint(content_signature_configuration)
    end

    def recorded_signature
      signature_store.read
    end

    def content_signature_configuration
      {
        version: CONTENT_SIGNATURE_VERSION,
        target: name,
        inputs: content_inputs,
        env: content_env,
        params_set: @content_params_set,
        params: content_params,
        action_version: action_version
      }
    end

    private

    def verify_output
      return if File.file?(name)
      fail Rake::FileContentOutputError,
           "content file task #{name.inspect} did not produce a regular file"
    end

    def record_signature
      signature_store.write(
        current_signature,
        current_signature_fingerprint
      )
    end

    def signature_store
      @signature_store ||= FileContentSignatureStore.new(name, signature_dir)
    end
  end

  # Raised when a content file action finishes but does not leave a valid
  # regular file at the target path.
  class FileContentOutputError < StandardError
  end

  # Builds a stable, typed signature for a target, its inputs, environment,
  # parameters, and the action version.
  class FileContentSignature
    def initialize(configuration)
      @configuration = configuration
    end

    def to_s
      Digest::SHA256.hexdigest(JSON.generate(to_h))
    end

    def to_h
      canonical_payload
    end

    private

    def canonical_payload
      {
        version: @configuration.fetch(:version),
        action_version: canonical_value(@configuration.fetch(:action_version)),
        target: file_signature(@configuration.fetch(:target)),
        inputs: @configuration.fetch(:inputs).sort.map { |path|
          file_signature(path)
        },
        environment: @configuration.fetch(:env).sort.map { |name|
          {
            "name" => name,
            "state" => environment_state(name),
            "digest" => environment_digest(name)
          }
        },
        params: @configuration.fetch(:params_set) ?
                  canonical_value(@configuration.fetch(:params)) :
                  { "__type__" => "missing" }
      }
    end

    def environment_state(name)
      return "missing" unless ENV.key?(name)
      ENV.fetch(name).empty? ? "empty" : "present"
    end

    def environment_digest(name)
      digest_string(ENV.fetch(name)) if ENV.key?(name)
    end

    def file_signature(path, active_symlinks=nil)
      stat = File.lstat(path)
      result = { "path" => path, "type" => stat.ftype }

      case
      when stat.symlink?
        target = File.readlink(path)
        resolved_target = File.expand_path(target, File.dirname(path))
        result["target"] = target
        result["target_signature"] = target_signature(resolved_target, active_symlinks)
      when stat.file?
        result["digest"] = digest_file(path)
      when stat.directory?
        result["entries"] = directory_entries(path, active_symlinks)
      end

      result
    rescue Errno::ENOENT
      { "path" => path, "type" => "missing" }
    end

    def target_signature(path, active_symlinks)
      if active_symlinks&.include?(path)
        return { "path" => path, "type" => "symlink_loop" }
      end

      following = (active_symlinks || Set.new).dup
      following.add(path)
      file_signature(path, following)
    end

    def directory_entries(path, active_symlinks)
      entries = Dir.entries(path) - [".", ".."]
      entries.sort.map do |entry|
        file_signature(File.join(path, entry), active_symlinks)
      end
    end

    def digest_file(path)
      Digest::SHA256.file(path).hexdigest
    end

    def digest_string(value)
      Digest::SHA256.hexdigest(value.to_s)
    end

    def canonical_value(value)
      case value
      when nil then { "__type__" => "nil" }
      when true, false then { "__type__" => value.class.name, "value" => value }
      when String then { "__type__" => "String", "value" => value }
      when Symbol then { "__type__" => "Symbol", "value" => value.to_s }
      when Integer then { "__type__" => "Integer", "value" => value }
      when Float then { "__type__" => "Float", "value" => value }
      when Array
        items = value.map { |item| canonical_value(item) }
        { "__type__" => "Array", "value" => items }
      when Hash
        entries = value.keys.sort_by(&:to_s).map do |key|
          [canonical_value(key), canonical_value(value[key])]
        end
        { "__type__" => "Hash", "value" => entries }
      when Pathname
        canonical_value(value.to_s)
      else
        raise ArgumentError, "unsupported content signature parameter: #{value.class}"
      end
    end
  end

  # Persists one target's signature independently of its output file so that
  # externally rewriting the output also invalidates the task.
  class FileContentSignatureStore
    def initialize(target, directory)
      @target = target
      @directory = directory
    end

    def read
      JSON.parse(File.read(path)).fetch("signature")
    rescue Errno::ENOENT, JSON::ParserError, KeyError
      nil
    end

    def write(signature, fingerprint)
      FileUtils.mkdir_p(@directory)
      temporary_name = ".#{File.basename(path)}.#{SecureRandom.hex(8)}"
      temporary_path = File.join(@directory, temporary_name)
      File.write(temporary_path, JSON.pretty_generate(
        "version" => Rake::FileContentTask::CONTENT_SIGNATURE_VERSION,
        "target" => @target,
        "signature" => signature,
        "fingerprint" => fingerprint
      ))
      File.rename(temporary_path, path)
    rescue Exception
      FileUtils.rm_f(temporary_path) if temporary_path
      raise
    end

    private

    def path
      target_digest = Digest::SHA256.hexdigest(File.expand_path(@target))
      @path ||= File.join(@directory, "#{target_digest}.json")
    end
  end
end
