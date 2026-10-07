# frozen_string_literal: true
require "digest"
require "fileutils"
require "json"
require "tempfile"

require_relative "file_task"

module Rake

  # A ContentFileTask rebuilds a file from the content of its declared inputs
  # rather than from modification times.  It records a signature after an
  # action succeeds and the resulting artifact passes validation.
  #
  class ContentFileTask < FileTask

    # Raised when an action completes but its artifact fails validation.
    class InvalidArtifact < StandardError; end

    MISSING = Object.new.freeze # :nodoc:

    attr_reader :action_version, :artifact_validator, :environment_variables,
                :input_files, :parameters, :signature_file

    def initialize(task_name, app) # :nodoc:
      super
      @input_files = []
      @environment_variables = []
      @parameters = {}
      @signature_file = nil
      @artifact_validator = nil
      @current_args = EMPTY_TASK_ARGS
    end

    # Configure the content used to determine whether the file is current.
    def configure(action_version:, inputs: [], env: [], environment: nil,
                  params: nil, parameters: nil, signature_file: nil, verify: nil)
      if action_version.nil?
        raise ArgumentError, "action_version is required"
      end
      if verify && !verify.respond_to?(:call)
        raise ArgumentError, "verify must respond to call"
      end

      @action_version = action_version
      @input_files |= Array(inputs).map { |path| Rake.from_pathname(path).to_s }
      env_names = environment || env
      signed_parameters = parameters || params || {}
      @environment_variables |= Array(env_names).map(&:to_s)
      normalized_parameters = signed_parameters.each_with_object({}) do |(key, value), result|
        result[key.to_s] = value
      end
      @parameters = @parameters.merge(normalized_parameters)
      @signature_file = signature_file.to_s if signature_file
      @artifact_validator = verify
      self
    end

    # Is this file task needed?  Yes if its recorded content signature is
    # missing, malformed, or different from the current content signature.
    def needed?
      if @application.options.build_all
        @outdated_reason = "build all is enabled"
        return true
      end

      @outdated_reason = outdated_reason
      !@outdated_reason.nil?
    end

    # Late while the content signature is stale; otherwise the artifact's
    # modification time, so ordinary dependent file tasks still compare safely.
    def timestamp
      return Rake::LATE if needed?

      super
    rescue Errno::ENOENT
      Rake::LATE
    end

    def invoke_with_call_chain(task_args, invocation_chain) # :nodoc:
      @current_args = task_args
      super
    end

    def prerequisite_tasks # :nodoc:
      (prerequisites + order_only_prerequisites).map do |prerequisite|
        lookup_content_prerequisite(prerequisite)
      end.compact
    end

    def execute(args=nil) # :nodoc:
      super
      return if application.options.dryrun

      validate_artifact!
      record_signature
    end

    # Human-readable explanation of why the task is outdated, or nil when the
    # recorded signature matches the current signature.
    def outdated_reason
      status, stored = stored_signature
      return "signature file is missing: #{signature_file_name}" if status == :missing
      return "signature file is malformed: #{stored}" if status == :malformed

      current = current_signature
      signature_difference(stored, current)
    end

    # Build the current content signature without persisting it.
    def current_signature
      {
        "signature_version" => 1,
        "action_version" => action_version,
        "target" => fingerprint_path(name),
        "inputs" => input_files.sort.map { |path| fingerprint_path(path) },
        "environment" => environment_variables.sort.map { |name|
          environment_fingerprint(name)
        },
        "parameters" => parameter_manifest.sort.to_h
      }
    end

    # Read and parse the recorded content signature.
    def stored_signature
      return [:missing, signature_file_name] unless File.exist?(signature_file_name)

      signature = JSON.parse(File.read(signature_file_name))
      unless valid_signature?(signature)
        return [:malformed, "unsupported signature version"]
      end

      [:ok, signature]
    rescue JSON::ParserError, SystemCallError => error
      [:malformed, error.message]
    end

    private

    def lookup_content_prerequisite(prerequisite_name)
      prerequisite_task = application.lookup(prerequisite_name, @scope)
      if prerequisite_task == self
        application.lookup(prerequisite_name)
      else
        prerequisite_task || resolve_missing_prerequisite(prerequisite_name)
      end
    end

    def resolve_missing_prerequisite(prerequisite_name)
      if input_files.include?(prerequisite_name)
        application.enhance_with_matching_rule(prerequisite_name)
      else
        application[prerequisite_name, @scope]
      end
    end

    def valid_signature?(signature)
      signature.is_a?(Hash) &&
        signature["signature_version"] == 1 &&
        signature.key?("action_version") &&
        valid_fingerprint?(signature["target"]) &&
        Array(signature["inputs"]).all? { |item| valid_fingerprint?(item) } &&
        Array(signature["environment"]).all? { |item|
          item.is_a?(Hash) && item["name"].is_a?(String) &&
            item["state"].is_a?(String)
        } &&
        signature["parameters"].is_a?(Hash) &&
        signature["parameters"].values.all? { |item|
          item.is_a?(Hash) && item["state"].is_a?(String)
        }
    end

    def valid_fingerprint?(fingerprint)
      fingerprint.is_a?(Hash) &&
        fingerprint["path"].is_a?(String) &&
        fingerprint["type"].is_a?(String)
    end

    def signature_file_name
      @signature_file || "#{name}.rake-content-signature"
    end

    def validate_artifact!
      if artifact_validator
        valid =
          if artifact_validator.respond_to?(:lambda?) && artifact_validator.lambda? &&
             artifact_validator.arity.zero?
            artifact_validator.call
          else
            artifact_validator.call(self)
          end
        unless valid
          raise InvalidArtifact,
                "artifact failed validation: #{name}"
        end
      elsif !File.file?(name)
        raise InvalidArtifact, "expected artifact was not created: #{name}"
      end
    end

    def record_signature
      signature = current_signature
      JSON.generate(signature)

      directory = File.dirname(signature_file_name)
      FileUtils.mkdir_p(directory)

      tempfile = Tempfile.new(
        [".rake-content-signature", ".tmp"], directory
      )
      begin
        tempfile.write(JSON.pretty_generate(signature))
        tempfile.close
        File.rename(tempfile.path, signature_file_name)
      rescue
        tempfile.close!
        raise
      end
    end

    def signature_difference(stored, current, prefix=nil)
      stored_keys = stored.is_a?(Hash) ? stored.keys : []
      current_keys = current.is_a?(Hash) ? current.keys : []

      (stored_keys | current_keys).each do |key|
        next if stored[key] == current[key]

        label = [prefix, key].compact.join(" ")
        next_reason = value_difference(label, stored[key], current[key])
        return next_reason if next_reason
      end

      nil
    end

    def value_difference(label, stored, current)
      if stored.is_a?(Hash) && stored["path"] && current.is_a?(Hash) && current["path"]
        return fingerprint_difference(label, stored, current)
      end

      case label
      when "action_version"
        "action version changed from #{stored.inspect} to #{current.inspect}"
      when "target"
        fingerprint_difference("target", stored, current)
      when "inputs", "environment", "parameters"
        if label == "parameters" && stored.is_a?(Hash) && current.is_a?(Hash)
          parameter_difference(stored, current)
        else
          collection_difference(label, stored, current)
        end
      else
        "#{label} changed"
      end
    end

    def collection_difference(label, stored, current)
      stored = Array(stored)
      current = Array(current)
      identity = lambda do |item|
        item.is_a?(Hash) ? (item["path"] || item["name"] || item["parameter"]) : item
      end
      stored_by = stored.map { |item| [identity.call(item), item] }.to_h
      current_by = current.map { |item| [identity.call(item), item] }.to_h

      (stored_by.keys | current_by.keys).each do |identity_key|
        next if stored_by[identity_key] == current_by[identity_key]

        singular = label.sub(/s$/, "")
        if stored_by[identity_key].is_a?(Hash) || current_by[identity_key].is_a?(Hash)
          return fingerprint_difference("#{singular} #{identity_key}",
                                        stored_by[identity_key],
                                        current_by[identity_key])
        end
        return "#{singular} #{identity_key} changed"
      end

      nil
    end

    def fingerprint_difference(label, stored, current)
      stored ||= {}
      current ||= {}
      path = current["path"] || stored["path"]
      stored_type = stored["type"]
      current_type = current["type"]

      location = label == "target" ? "#{label} #{path}" : label

      if stored["state"] != current["state"] &&
         (stored.key?("state") || current.key?("state"))
        return "#{location} state changed from #{stored["state"].inspect} to #{current["state"].inspect}"
      end
      return "#{location} is missing" if current_type == "missing"
      return "#{location} appeared" if stored_type == "missing"
      return "#{location} changed type from #{stored_type} to #{current_type}" if
        stored_type != current_type
      return "#{location} changed symlink target from #{stored["target"]} to #{current["target"]}" if
        stored["target"] != current["target"]
      return fingerprint_difference("#{label} target",
                                    stored["target_fingerprint"],
                                    current["target_fingerprint"]) if
        stored["target_fingerprint"] != current["target_fingerprint"]
      return "#{location} changed" if
        stored["digest"] != current["digest"] || stored["state"] != current["state"]

      "#{location} changed"
    end

    def parameter_difference(stored, current)
      (stored.keys | current.keys).each do |name|
        next if stored[name] == current[name]

        if !current.key?(name)
          return "parameter #{name} is missing"
        elsif !stored.key?(name)
          return "parameter #{name} was added"
        elsif stored[name]["state"] != current[name]["state"]
          stored_state = stored[name]["state"].inspect
          current_state = current[name]["state"].inspect
          return "parameter #{name} state changed from #{stored_state} to #{current_state}"
        else
          return "parameter #{name} changed"
        end
      end

      nil
    end

    def fingerprint_path(path, depth=0)
      absolute_path = File.expand_path(path.to_s)
      stat = File.lstat(absolute_path)

      if stat.symlink?
        target = File.readlink(absolute_path)
        target_path = File.expand_path(target, File.dirname(absolute_path))
        target_fingerprint =
          if depth >= 10
            { "path" => target_path, "type" => "error", "error" => "symlink loop" }
          else
            fingerprint_path(target_path, depth + 1)
          end
        {
          "path" => absolute_path,
          "type" => "symlink",
          "target" => target,
          "target_fingerprint" => target_fingerprint
        }
      elsif stat.file?
        {
          "path" => absolute_path,
          "type" => "file",
          "size" => stat.size,
          "digest" => Digest::SHA256.file(absolute_path).hexdigest
        }
      else
        { "path" => absolute_path, "type" => stat.ftype }
      end
    rescue Errno::ENOENT
      { "path" => absolute_path, "type" => "missing" }
    end

    def environment_fingerprint(name)
      if !ENV.key?(name)
        { "name" => name, "state" => "missing" }
      elsif ENV[name].nil?
        { "name" => name, "state" => "null" }
      else
        { "name" => name, "state" => "present" }.
          merge(string_fingerprint(ENV[name]))
      end
    end

    def parameter_manifest
      parameters = @parameters.dup

      Array(@current_args.names).each_with_index do |name, index|
        values = @current_args.to_a
        parameters[name.to_s] =
          if index >= values.length
            MISSING
          else
            values[index]
          end
      end

      parameters.sort.map do |name, value|
        [name, parameter_fingerprint(value)]
      end.to_h
    end

    def parameter_fingerprint(value)
      return { "state" => "missing" } if value.equal?(MISSING)
      return { "state" => "null" } if value.nil?

      { "state" => "present" }.merge(typed_value_fingerprint(value))
    end

    def typed_value_fingerprint(value)
      case value
      when String
        string_fingerprint(value)
      when Integer, Float, TrueClass, FalseClass
        { "type" => value.class.name, "value" => value }
      when Array
        { "type" => "array", "value" => value.map { |item| parameter_fingerprint(item) } }
      when Hash
        {
          "type" => "hash",
          "value" => value.sort.map { |key, item|
            [key.to_s, parameter_fingerprint(item)]
          }.to_h
        }
      when Symbol
        { "type" => "Symbol", "value" => value.to_s }
      else
        raise ArgumentError, "unsupported parameter type: #{value.class}"
      end
    end

    def string_fingerprint(value)
      {
        "type" => "String",
        "length" => value.bytesize,
        "digest" => Digest::SHA256.hexdigest(value)
      }
    end

    class << self
      # Apply the scope to the task name according to the rules for this kind
      # of task. File based tasks ignore the scope when creating the name.
      def scope_name(scope, task_name)
        Rake.from_pathname(task_name)
      end
    end
  end
end
