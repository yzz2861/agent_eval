# frozen_string_literal: true

module JSON
  # = JSON::Patch -- RFC 6902 structural diff and patch application
  #
  # JSON::Patch compares two JSON documents (as Ruby objects) and produces an
  # RFC 6902 JSON Patch: a sequence of +add+, +remove+, +replace+ and +move+
  # operations that transforms the source document into the target document.
  #
  #   patch = JSON::Patch.diff(source, target)
  #   JSON::Patch.apply(source, patch) == target # => true
  #
  # == Array element identity
  #
  # Arrays are the hard part of structural diffing: without extra information
  # a reorder is indistinguishable from a rewrite. Pass +array_identity+ (any
  # callable) to tell JSON::Patch.diff how to read the stable identity of an
  # array element:
  #
  #   patch = JSON::Patch.diff(old_users, new_users,
  #                            array_identity: ->(user) { user["id"] })
  #
  # When every element of both arrays has a unique identity, reordered
  # elements produce +move+ operations and edited elements produce nested
  # diffs. When no identity is given, or when an identity value is repeated
  # on either side, JSON::Patch falls back to a conservative positional
  # strategy that only emits +add+/+remove+/+replace+ and never guesses a
  # +move+.
  #
  # == Paths
  #
  # Operation paths are RFC 6901 JSON Pointers; +~+ and +/+ inside object
  # keys are escaped as +~0+ and +~1+. Operations are ordered so that, when
  # applied sequentially, every array index still refers to the intended
  # element.
  module Patch
    # Raised when a patch cannot be applied to a document.
    Error = Class.new(StandardError)

    OP_ADD = "add"
    OP_REMOVE = "remove"
    OP_REPLACE = "replace"
    OP_MOVE = "move"

    module_function

    # Returns an RFC 6902 patch (an Array of operation Hashes with String
    # keys) that transforms +old_document+ into +new_document+.
    #
    # +array_identity+ is an optional callable returning the stable identity
    # of an array element; see the module documentation.
    def diff(old_document, new_document, array_identity: nil)
      operations = []
      diff_value(old_document, new_document, +"", operations, array_identity)
      operations
    end

    # Returns a new document produced by applying +patch+ (an Array of
    # operation Hashes, as returned by JSON::Patch.diff) to +document+.
    # Neither +document+ nor +patch+ is mutated.
    #
    # This doubles as a standalone patch verifier:
    #
    #   JSON::Patch.apply(source, patch) == target
    #
    # Raises JSON::Patch::Error when an operation is malformed or references
    # a location that does not exist.
    def apply(document, patch)
      root = deep_dup(document)
      patch.each do |operation|
        root = apply_operation(root, operation)
      end
      root
    end

    # -- diffing ----------------------------------------------------------

    def diff_value(old_value, new_value, path, operations, array_identity)
      if old_value.is_a?(Hash) && new_value.is_a?(Hash)
        diff_hash(old_value, new_value, path, operations, array_identity)
      elsif old_value.is_a?(Array) && new_value.is_a?(Array)
        diff_array(old_value, new_value, path, operations, array_identity)
      elsif !json_equal?(old_value, new_value)
        operations << { "op" => OP_REPLACE, "path" => path, "value" => new_value }
      end
    end

    def diff_hash(old_hash, new_hash, path, operations, array_identity)
      old_hash.each_key do |key|
        unless new_hash.key?(key)
          operations << { "op" => OP_REMOVE, "path" => build_path(path, key) }
        end
      end
      old_hash.each do |key, old_child|
        if new_hash.key?(key)
          diff_value(old_child, new_hash[key], build_path(path, key), operations, array_identity)
        end
      end
      new_hash.each do |key, new_child|
        unless old_hash.key?(key)
          operations << { "op" => OP_ADD, "path" => build_path(path, key), "value" => new_child }
        end
      end
    end

    def diff_array(old_array, new_array, path, operations, array_identity)
      if array_identity
        ids = begin
          [old_array.map { |element| array_identity.call(element) },
           new_array.map { |element| array_identity.call(element) }]
        rescue StandardError
          # The identity reader cannot handle every element: treat the array
          # as if no identity were available.
          nil
        end
        if ids && ids[0].uniq.size == ids[0].size && ids[1].uniq.size == ids[1].size
          old_ids, new_ids = ids
          return diff_array_by_identity(old_array, new_array, old_ids, new_ids, path, operations, array_identity)
        end
        # Duplicate identities would make moves ambiguous: fall through to
        # the conservative strategy.
      end
      diff_array_conservative(old_array, new_array, path, operations, array_identity)
    end

    # Conservative strategy: never emits +move+. Equal prefixes and suffixes
    # are kept untouched, the differing middle is paired up positionally for
    # nested diffs, and any length difference becomes trailing +remove+
    # (descending indices) or +add+ (ascending indices) operations.
    def diff_array_conservative(old_array, new_array, path, operations, array_identity)
      min_size = [old_array.size, new_array.size].min

      prefix = 0
      while prefix < min_size && json_equal?(old_array[prefix], new_array[prefix])
        prefix += 1
      end

      suffix = 0
      while suffix < min_size - prefix &&
            json_equal?(old_array[old_array.size - 1 - suffix], new_array[new_array.size - 1 - suffix])
        suffix += 1
      end

      old_mid_end = old_array.size - suffix
      new_mid_end = new_array.size - suffix
      paired = [old_mid_end - prefix, new_mid_end - prefix].min

      paired.times do |offset|
        index = prefix + offset
        diff_value(old_array[index], new_array[index], "#{path}/#{index}", operations, array_identity)
      end

      (old_mid_end - 1).downto(prefix + paired) do |index|
        operations << { "op" => OP_REMOVE, "path" => "#{path}/#{index}" }
      end

      (prefix + paired...new_mid_end).each do |index|
        operations << { "op" => OP_ADD, "path" => "#{path}/#{index}", "value" => new_array[index] }
      end
    end

    # Identity-based strategy: emits +move+ for kept elements whose position
    # changed, +add+/+remove+ for appearing/disappearing identities, and
    # nested diffs for kept elements whose content changed.
    #
    # Kept elements are first aligned in relative order using a minimum
    # number of moves (the complement of a longest increasing subsequence of
    # target positions stays put), then new elements are added at their final
    # indices. The +current+ array simulates the document as operations are
    # emitted, so every index is valid at the point its operation is applied.
    def diff_array_by_identity(old_array, new_array, old_ids, new_ids, path, operations, array_identity)
      current = old_ids.dup
      in_new = {}
      new_ids.each { |id| in_new[id] = true }
      in_old = {}
      old_ids.each { |id| in_old[id] = true }

      (current.size - 1).downto(0) do |index|
        unless in_new[current[index]]
          operations << { "op" => OP_REMOVE, "path" => "#{path}/#{index}" }
          current.delete_at(index)
        end
      end

      target_kept = new_ids.select { |id| in_old[id] }
      if current != target_kept
        target_position = {}
        target_kept.each_with_index { |id, index| target_position[id] = index }
        stayers = {}
        lis_indices(current.map { |id| target_position[id] }).each do |index|
          stayers[current[index]] = true
        end
        index = 0
        while index < target_kept.size
          if current[index] == target_kept[index]
            index += 1
          elsif stayers[target_kept[index]]
            # The wanted element stays put; push the element in the way (a
            # mover by construction) directly to its final position.
            to = target_position[current[index]]
            operations << { "op" => OP_MOVE, "from" => "#{path}/#{index}", "path" => "#{path}/#{to}" }
            current.insert(to, current.delete_at(index))
          else
            from = current.index(target_kept[index])
            operations << { "op" => OP_MOVE, "from" => "#{path}/#{from}", "path" => "#{path}/#{index}" }
            current.insert(index, current.delete_at(from))
            index += 1
          end
        end
      end

      new_ids.each_with_index do |id, index|
        unless in_old[id]
          operations << { "op" => OP_ADD, "path" => "#{path}/#{index}", "value" => new_array[index] }
        end
      end

      old_index_by_id = {}
      old_ids.each_with_index { |id, old_index| old_index_by_id[id] = old_index }
      new_ids.each_with_index do |id, new_index|
        old_index = old_index_by_id[id]
        next unless old_index
        diff_value(old_array[old_index], new_array[new_index], "#{path}/#{new_index}", operations, array_identity)
      end
    end

    # Deep equality that also distinguishes values JSON serializes
    # differently, such as 1 and 1.0.
    def json_equal?(old_value, new_value)
      if old_value.is_a?(Hash) && new_value.is_a?(Hash)
        old_value.size == new_value.size &&
          old_value.all? { |key, child| new_value.key?(key) && json_equal?(child, new_value[key]) }
      elsif old_value.is_a?(Array) && new_value.is_a?(Array)
        old_value.size == new_value.size &&
          old_value.each_index.all? { |index| json_equal?(old_value[index], new_value[index]) }
      else
        old_value.class == new_value.class && old_value == new_value
      end
    end

    # -- patch application -------------------------------------------------

    def apply_operation(root, operation)
      op = operation_key(operation, "op")
      case op
      when OP_ADD
        value = deep_dup(operation_key(operation, "value"))
        pointer = parse_pointer(operation_key(operation, "path"))
        return value if pointer.empty?
        parent, token = navigate(root, pointer)
        add_child(parent, token, value)
        root
      when OP_REMOVE
        pointer = parse_pointer(operation_key(operation, "path"))
        raise Error, "cannot remove the document root" if pointer.empty?
        parent, token = navigate(root, pointer)
        remove_child(parent, token)
        root
      when OP_REPLACE
        value = deep_dup(operation_key(operation, "value"))
        pointer = parse_pointer(operation_key(operation, "path"))
        return value if pointer.empty?
        parent, token = navigate(root, pointer)
        replace_child(parent, token, value)
        root
      when OP_MOVE
        from = parse_pointer(operation_key(operation, "from"))
        pointer = parse_pointer(operation_key(operation, "path"))
        if from.size < pointer.size && pointer[0, from.size] == from
          raise Error, '"from" must not be a proper prefix of "path"'
        end
        if from.empty?
          raise Error, "cannot move the document root into itself" unless pointer.empty?
          return root
        end
        parent, token = navigate(root, from)
        value = remove_child(parent, token)
        return value if pointer.empty?
        parent, token = navigate(root, pointer)
        add_child(parent, token, value)
        root
      else
        raise Error, "unsupported patch operation: #{op.inspect}"
      end
    end

    def operation_key(operation, key)
      if operation.key?(key)
        operation[key]
      elsif operation.key?(key.to_sym)
        operation[key.to_sym]
      else
        raise Error, "patch operation is missing #{key.inspect}"
      end
    end

    def parse_pointer(pointer)
      return [] if pointer.empty?
      unless pointer.start_with?("/")
        raise Error, "invalid JSON pointer: #{pointer.inspect}"
      end
      pointer.split("/", -1)[1..].map { |token| unescape_token(token) }
    end

    def navigate(root, pointer)
      node = root
      pointer[0...-1].each do |token|
        node = fetch_child(node, token)
      end
      [node, pointer[-1]]
    end

    def fetch_child(node, token)
      case node
      when Hash
        raise Error, "no such object member: #{token.inspect}" unless node.key?(token)
        node[token]
      when Array
        index = array_index(token)
        raise Error, "array index out of bounds: #{index}" if index >= node.size
        node[index]
      else
        raise Error, "cannot traverse into #{node.class}"
      end
    end

    def add_child(parent, token, value)
      case parent
      when Hash
        parent[token] = value
      when Array
        if token == "-"
          parent << value
        else
          index = array_index(token)
          raise Error, "array index out of bounds: #{index}" if index > parent.size
          parent.insert(index, value)
        end
      else
        raise Error, "cannot add into #{parent.class}"
      end
    end

    def remove_child(parent, token)
      case parent
      when Hash
        raise Error, "no such object member: #{token.inspect}" unless parent.key?(token)
        parent.delete(token)
      when Array
        index = array_index(token)
        raise Error, "array index out of bounds: #{index}" if index >= parent.size
        parent.delete_at(index)
      else
        raise Error, "cannot remove from #{parent.class}"
      end
    end

    def replace_child(parent, token, value)
      case parent
      when Hash
        raise Error, "no such object member: #{token.inspect}" unless parent.key?(token)
        parent[token] = value
      when Array
        index = array_index(token)
        raise Error, "array index out of bounds: #{index}" if index >= parent.size
        parent[index] = value
      else
        raise Error, "cannot replace in #{parent.class}"
      end
    end

    def array_index(token)
      unless /\A(0|[1-9]\d*)\z/.match?(token)
        raise Error, "invalid array index: #{token.inspect}"
      end
      token.to_i
    end

    # -- helpers -----------------------------------------------------------

    # Returns the indices of +sequence+ (an Array of Integers) that form a
    # longest strictly increasing subsequence. Runs in O(n log n).
    def lis_indices(sequence)
      tails = []
      parents = {}
      sequence.each_with_index do |value, index|
        low = 0
        high = tails.size
        while low < high
          mid = (low + high) / 2
          if sequence[tails[mid]] < value
            low = mid + 1
          else
            high = mid
          end
        end
        parents[index] = tails[low - 1] if low > 0
        tails[low] = index
      end
      indices = []
      index = tails.last
      while index
        indices.unshift(index)
        index = parents[index]
      end
      indices
    end

    def build_path(path, key)
      "#{path}/#{escape_token(key)}"
    end

    def escape_token(token)
      token.to_s.gsub("~", "~0").gsub("/", "~1")
    end

    def unescape_token(token)
      token.gsub("~1", "/").gsub("~0", "~")
    end

    def deep_dup(value)
      case value
      when Hash
        value.each_with_object({}) { |(key, child), copy| copy[key] = deep_dup(child) }
      when Array
        value.map { |element| deep_dup(element) }
      when String
        value.dup
      else
        value
      end
    end
  end
end
