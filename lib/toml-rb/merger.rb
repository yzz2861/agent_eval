# frozen_string_literal: true

module TomlRB
  class DeleteValue
    def inspect
      "TomlRB::DELETE"
    end

    alias to_s inspect
  end

  DELETE = DeleteValue.new.freeze

  class DeleteMember
    attr_reader :identity_key, :identity_value

    def initialize(identity_key, identity_value)
      if identity_key.nil? || identity_key.to_s.empty? || identity_value.nil?
        raise ArgumentError, "identity key and identity value are required"
      end

      @identity_key = identity_key.to_s
      @identity_value = identity_value
      freeze
    end

    def inspect
      "#<TomlRB::DeleteMember #{identity_key.inspect}=#{identity_value.inspect}>"
    end

    def ==(other)
      other.is_a?(DeleteMember) &&
        identity_key == other.identity_key &&
        identity_value == other.identity_value
    end

    alias eql? ==

    def hash
      [identity_key, identity_value].hash
    end
  end

  class Merger
    def initialize(array_table_rules)
      @rules = normalize_rules(array_table_rules)
    end

    def merge(layers)
      layers.each_with_object({}) do |layer, result|
        unless layer.is_a?(Hash)
          raise ArgumentError, "configuration layer must be a Hash, got #{layer.class}"
        end

        merge_hash!(result, deep_copy(layer), [], nil)
      end
    end

    private

    def normalize_rules(rules)
      unless rules.is_a?(Hash)
        raise ArgumentError, "array_tables must be a Hash, got #{rules.class}"
      end

      rules.each_with_object({}) do |(path, identity_key), normalized|
        key_path = normalize_rule_path(path)
        field = identity_key.to_s
        if key_path.empty? || field.empty?
          raise ArgumentError, "array table path and identity key are required"
        end
        if normalized.key?(key_path)
          raise ArgumentError, "duplicate array table rule: #{key_path.join(".")}"
        end

        normalized[key_path] = field
      end
    end

    def normalize_rule_path(path)
      case path
      when Array
        path.map { |key| validate_rule_key(key) }
      when String, Symbol
        path.to_s.split(".").map { |key| validate_rule_key(key) }
      else
        raise ArgumentError, "array table path must be a String, Symbol or Array, got #{path.class}"
      end
    end

    def validate_rule_key(key)
      key = key.to_s
      return key unless key.empty?

      raise ArgumentError, "array table path cannot contain an empty key"
    end

    def merge_hash!(target, incoming, rule_path, prefix)
      incoming.each do |incoming_key, incoming_value|
        key = matching_key(target, incoming_key)
        location = field_location(rule_path, key || incoming_key, prefix)

        if incoming_value.equal?(DELETE)
          target.delete(key) if key
          next
        end

        conflict!("#{location}: unexpected array member deletion") if incoming_value.is_a?(DeleteMember)

        current = key ? target[key] : :__missing__
        child_rule_path = rule_path + [incoming_key.to_s]
        rule = @rules[child_rule_path]

        if incoming_value.is_a?(Hash)
          merge_incoming_hash!(target, key || incoming_key, current, incoming_value,
            child_rule_path, rule, prefix, location)
        elsif incoming_value.is_a?(Array)
          merge_incoming_array!(target, key || incoming_key, current, incoming_value,
            child_rule_path, rule, prefix, location)
        else
          if current.is_a?(Hash)
            conflict!("#{location}: cannot replace table with #{type_name(incoming_value)}")
          end
          if rule && current.is_a?(Array)
            conflict!("#{location}: cannot replace array table with #{type_name(incoming_value)}")
          end

          target[key || incoming_key] = incoming_value
        end
      end

      target
    end

    def merge_incoming_hash!(target, key, current, incoming, rule_path, declared_array_table, prefix, location)
      if current == :__missing__
        target[key] = merge_hash!({}, incoming, rule_path, prefix)
      elsif current.is_a?(Hash)
        merge_hash!(current, incoming, rule_path, prefix)
      elsif current.is_a?(Array) && declared_array_table
        conflict!("#{location}: cannot replace array table with table")
      elsif current.is_a?(Array)
        target[key] = merge_hash!({}, incoming, rule_path, prefix)
      else
        conflict!("#{location}: cannot replace #{type_name(current)} with table")
      end
    end

    def merge_incoming_array!(target, key, current, incoming, rule_path, rule, prefix, location)
      if rule
        merge_table_array!(target, key, current, incoming, rule_path, rule, prefix, location)
      else
        target[key] = sanitize_ordinary_array!(incoming, rule_path, prefix)
      end
    end

    def merge_table_array!(target, key, current, incoming, rule_path, identity_key, prefix, location)
      existing =
        if current == :__missing__
          []
        elsif current.is_a?(Array)
          current
        else
          conflict!("#{location}: cannot replace #{type_name(current)} with array table")
        end

      validate_existing_table_array!(existing, rule_path, identity_key, prefix)
      validate_incoming_table_array!(incoming, rule_path, identity_key, prefix)

      incoming.each do |entry|
        if entry.is_a?(DeleteMember)
          index = member_index(existing, identity_key, entry.identity_value)
          existing.delete_at(index) if index
          next
        end

        identity = member_identity(entry, identity_key, rule_path, prefix)
        index = member_index(existing, identity_key, identity)
        member_prefix = member_location(rule_path, identity, prefix)

        if index
          merge_hash!(existing[index], entry, rule_path, member_prefix)
        else
          existing << merge_hash!({}, entry, rule_path, member_prefix)
        end
      end

      target[key] = existing
    end

    def validate_existing_table_array!(array, rule_path, identity_key, prefix)
      identities = {}

      array.each do |entry|
        unless entry.is_a?(Hash)
          conflict!("#{array_location(rule_path, prefix)}: array table member must be a table")
        end

        identity = member_identity(entry, identity_key, rule_path, prefix)
        count_identity!(identities, identity, rule_path, identity_key, prefix)
      end
    end

    def validate_incoming_table_array!(array, rule_path, identity_key, prefix)
      identities = {}

      array.each do |entry|
        unless entry.is_a?(Hash) || entry.is_a?(DeleteMember)
          conflict!("#{array_location(rule_path, prefix)}: array table member must be a table")
        end

        if entry.is_a?(DeleteMember)
          unless entry.identity_key == identity_key
            location = array_location(rule_path, prefix)
            used = entry.identity_key.inspect
            expected = identity_key.inspect
            conflict!("#{location}: deletion uses #{used}, but rule uses #{expected}")
          end
          identity = entry.identity_value
        else
          identity = member_identity(entry, identity_key, rule_path, prefix)
        end

        count_identity!(identities, identity, rule_path, identity_key, prefix)
      end
    end

    def member_identity(member, identity_key, rule_path, prefix)
      identity_key_matches = member.keys.find { |key| key.to_s == identity_key }
      identity = member[identity_key_matches]

      if identity.nil?
        location = array_location(rule_path, prefix)
        conflict!("#{location}: array table entry is missing identity field #{identity_key.inspect}")
      elsif identity.equal?(DELETE) || identity.is_a?(DeleteMember)
        location = array_location(rule_path, prefix)
        conflict!("#{location}: array table identity field #{identity_key.inspect} cannot be deleted")
      end

      identity
    end

    def count_identity!(identities, identity, rule_path, identity_key, prefix)
      identities[identity] = identities.fetch(identity, 0) + 1
      return unless identities[identity] > 1

      location = array_location(rule_path, prefix)
      conflict!("#{location}: has duplicate identity #{identity.inspect} for #{identity_key.inspect}")
    end

    def member_index(array, identity_key, identity)
      array.index do |member|
        key = matching_key(member, identity_key)
        key && member[key] == identity
      end
    end

    def sanitize_ordinary_array!(array, rule_path, prefix)
      array.each_with_index do |value, index|
        if value.equal?(DELETE) || value.is_a?(DeleteMember)
          location = "#{array_location(rule_path, prefix)}[#{index}]"
          conflict!("#{location}: explicit deletion is not valid in an ordinary array")
        end

        array[index] = sanitize_ordinary_value!(value)
      end
    end

    def sanitize_ordinary_value!(value)
      case value
      when Hash
        sanitize_ordinary_hash!(value)
      when Array
        value.map! { |child| sanitize_ordinary_value!(child) }
        value
      else
        value
      end
    end

    def sanitize_ordinary_hash!(hash)
      hash.each do |key, value|
        if value.equal?(DELETE) || value.is_a?(DeleteMember)
          conflict!("#{key.inspect}: explicit deletion is not valid inside an ordinary array")
        end

        hash[key] = sanitize_ordinary_value!(value)
      end

      hash
    end

    def matching_key(hash, wanted_key)
      hash.keys.find { |key| key.to_s == wanted_key.to_s }
    end

    def deep_copy(value)
      case value
      when Hash
        value.each_with_object({}) do |(key, child), result|
          result[deep_copy(key)] = deep_copy(child)
        end
      when Array
        value.map { |child| deep_copy(child) }
      when DeleteValue, DeleteMember
        value
      when String, Time, Regexp
        value.dup
      else
        begin
          value.dup
        rescue TypeError
          value
        end
      end
    end

    def field_location(rule_path, key, prefix)
      if prefix
        key.nil? ? prefix : "#{prefix}.#{key}"
      else
        (rule_path + (key.nil? ? [] : [key.to_s])).join(".")
      end
    end

    def array_location(rule_path, prefix)
      prefix || rule_path.join(".")
    end

    def member_location(rule_path, identity, prefix)
      array_name = array_location(rule_path, prefix)
      identity_key = @rules[rule_path]
      "#{array_name}[#{identity_key}=#{identity.inspect}]"
    end

    def type_name(value)
      value.is_a?(Hash) ? "table" : value.class.name
    end

    def conflict!(message)
      raise MergeConflictError, message
    end
  end
end
