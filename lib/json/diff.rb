# frozen_string_literal: true

module JSON
  # = JSON Structural Diff (RFC 6902)
  #
  # JSON::Diff computes the structural difference between two JSON
  # documents (plain Ruby hashes, arrays and scalars) and emits an
  # RFC 6902 JSON Patch. Unlike a whole-document replacement, only the
  # parts that actually changed appear in the patch: object keys are
  # added, removed or recursed into individually, and arrays are
  # matched element by element instead of being replaced wholesale.
  #
  #   patch = JSON::Diff.generate(before, after)
  #   JSON::Diff.apply(before, patch) == after # => true
  #
  # == Array element identity
  #
  # Arrays of records often change by reordering or by inserting and
  # removing individual elements. Pass an +identity+ proc that maps an
  # element to a stable key (for example its id) so such edits are
  # expressed as +move+, +add+ and +remove+ operations:
  #
  #   JSON::Diff.generate(old_rows, new_rows, identity: ->(row) { row["id"] })
  #
  # A +move+ is only emitted when it is provably correct: if the
  # identity proc is missing, returns +nil+ for any element, or yields
  # duplicate keys on either side, the differ falls back to a
  # conservative positional comparison that never moves elements.
  #
  # == Ordering guarantees
  #
  # Operations are emitted so that applying them one by one keeps every
  # subsequent array index valid: elements are matched left to right
  # against a simulated working copy, and surplus elements are removed
  # from the tail in descending index order. Path tokens are escaped as
  # JSON Pointers (RFC 6901): <tt>~</tt> becomes <tt>~0</tt> and
  # <tt>/</tt> becomes <tt>~1</tt>.
  module Diff
    # Raised when a patch cannot be applied to a document.
    class PatchError < JSONError; end

    module_function

    # Returns an RFC 6902 JSON Patch (an array of operation hashes with
    # string keys) that transforms +old_document+ into +new_document+.
    #
    # +identity+ is an optional proc returning a stable identity key for
    # array elements, enabling +move+ detection (see above).
    def generate(old_document, new_document, identity: nil)
      operations = []
      diff_value(old_document, new_document, "", operations, identity)
      operations
    end

    # Applies an RFC 6902 +patch+ (as produced by ::generate) to
    # +document+ and returns the patched document. The input document
    # and patch are not modified. Supports the +add+, +remove+,
    # +replace+ and +move+ operations; this is a small standalone
    # verifier intended to check that a generated patch really
    # reproduces the target document.
    def apply(document, patch)
      result = deep_copy(document)
      patch.each do |operation|
        result = apply_operation(result, normalize_operation(operation))
      end
      result
    end

    # Escapes a single JSON Pointer reference token (RFC 6901).
    def escape_token(token)
      token.to_s.gsub("~", "~0").gsub("/", "~1")
    end

    # Splits a JSON Pointer into unescaped reference tokens.
    def parse_pointer(pointer)
      return [] if pointer.nil? || pointer.empty?
      unless pointer.start_with?("/")
        raise PatchError, "invalid JSON pointer: #{pointer.inspect}"
      end
      pointer.split("/", -1)[1..].map do |token|
        token.gsub("~1", "/").gsub("~0", "~")
      end
    end

    class << self
      private

      def diff_value(old_value, new_value, path, operations, identity)
        if old_value.is_a?(Hash) && new_value.is_a?(Hash)
          diff_object(old_value, new_value, path, operations, identity)
        elsif old_value.is_a?(Array) && new_value.is_a?(Array)
          diff_array(old_value, new_value, path, operations, identity)
        elsif !scalar_equal?(old_value, new_value)
          operations << { "op" => "replace", "path" => path, "value" => new_value }
        end
      end

      def scalar_equal?(old_value, new_value)
        old_value.class == new_value.class && old_value == new_value
      end

      def diff_object(old_object, new_object, path, operations, identity)
        old_object.each_key do |key|
          unless new_object.key?(key)
            operations << { "op" => "remove", "path" => "#{path}/#{escape_token(key)}" }
          end
        end
        new_object.each do |key, new_value|
          child_path = "#{path}/#{escape_token(key)}"
          if old_object.key?(key)
            diff_value(old_object[key], new_value, child_path, operations, identity)
          else
            operations << { "op" => "add", "path" => child_path, "value" => new_value }
          end
        end
      end

      def diff_array(old_array, new_array, path, operations, identity)
        old_ids = identity && old_array.map { |element| identity.call(element) }
        new_ids = identity && new_array.map { |element| identity.call(element) }
        if usable_identities?(old_ids) && usable_identities?(new_ids)
          diff_array_by_identity(old_array, new_array, old_ids, new_ids, path, operations, identity)
        else
          diff_array_positionally(old_array, new_array, path, operations, identity)
        end
      end

      # Identity keys are only trustworthy when every element has one
      # and no key is repeated; otherwise moving elements could target
      # the wrong entry, so the caller falls back to positional diffing.
      def usable_identities?(ids)
        ids && ids.none?(&:nil?) && ids.uniq.length == ids.length
      end

      # Conservative strategy: compare elements pairwise by index and
      # only ever append to or truncate the tail. Never emits +move+.
      def diff_array_positionally(old_array, new_array, path, operations, identity)
        common = [old_array.length, new_array.length].min
        common.times do |index|
          diff_value(old_array[index], new_array[index], "#{path}/#{index}", operations, identity)
        end
        (old_array.length - 1).downto(common) do |index|
          operations << { "op" => "remove", "path" => "#{path}/#{index}" }
        end
        (common...new_array.length).each do |index|
          operations << { "op" => "add", "path" => "#{path}/-", "value" => new_array[index] }
        end
      end

      # Matches elements by identity key against a simulated working
      # copy of the array, so every emitted index refers to the array
      # as it exists when the operation is applied.
      def diff_array_by_identity(old_array, new_array, old_ids, new_ids, path, operations, identity)
        working = old_array.each_with_index.map { |element, index| [old_ids[index], element] }
        new_array.each_with_index do |new_element, index|
          id = new_ids[index]
          if index < working.length && working[index][0] == id
            diff_value(working[index][1], new_element, "#{path}/#{index}", operations, identity)
          elsif (found = find_identity(working, id, index + 1))
            operations << { "op" => "move", "from" => "#{path}/#{found}", "path" => "#{path}/#{index}" }
            pair = working.delete_at(found)
            working.insert(index, pair)
            diff_value(pair[1], new_element, "#{path}/#{index}", operations, identity)
          else
            operations << { "op" => "add", "path" => "#{path}/#{index}", "value" => new_element }
            working.insert(index, [id, new_element])
          end
        end
        while working.length > new_array.length
          operations << { "op" => "remove", "path" => "#{path}/#{working.length - 1}" }
          working.pop
        end
      end

      def find_identity(working, id, start)
        index = start
        while index < working.length
          return index if working[index][0] == id
          index += 1
        end
        nil
      end

      def normalize_operation(operation)
        operation.each_with_object({}) { |(key, value), hash| hash[key.to_s] = value }
      end

      def apply_operation(document, operation)
        path = parse_pointer(operation.fetch("path"))
        case operation.fetch("op")
        when "add"
          add_at(document, path, deep_copy(operation["value"]))
        when "remove"
          remove_at(document, path).first
        when "replace"
          value = deep_copy(operation["value"])
          return value if path.empty?
          set_child(resolve_parent(document, path), path[-1], value)
          document
        when "move"
          document, value = remove_at(document, parse_pointer(operation.fetch("from")))
          add_at(document, path, value)
        else
          raise PatchError, "unsupported operation: #{operation["op"].inspect}"
        end
      end

      def resolve_parent(document, path)
        path[0..-2].reduce(document) { |node, token| fetch_child(node, token) }
      end

      def add_at(document, path, value)
        return value if path.empty?
        parent = resolve_parent(document, path)
        token = path[-1]
        case parent
        when Hash
          parent[token] = value
        when Array
          if token == "-"
            parent << value
          else
            index = array_index(token, parent.length)
            parent.insert(index, value)
          end
        else
          raise PatchError, "cannot add to #{parent.class}"
        end
        document
      end

      def remove_at(document, path)
        return [nil, document] if path.empty?
        parent = resolve_parent(document, path)
        token = path[-1]
        removed =
          case parent
          when Hash
            unless parent.key?(token)
              raise PatchError, "no such key to remove: #{token.inspect}"
            end
            parent.delete(token)
          when Array
            parent.delete_at(array_index(token, parent.length - 1))
          else
            raise PatchError, "cannot remove from #{parent.class}"
          end
        [document, removed]
      end

      def set_child(parent, token, value)
        case parent
        when Hash
          unless parent.key?(token)
            raise PatchError, "no such key to replace: #{token.inspect}"
          end
          parent[token] = value
        when Array
          parent[array_index(token, parent.length - 1)] = value
        else
          raise PatchError, "cannot replace in #{parent.class}"
        end
      end

      def fetch_child(node, token)
        case node
        when Hash
          unless node.key?(token)
            raise PatchError, "no such key: #{token.inspect}"
          end
          node[token]
        when Array
          node.fetch(array_index(token, node.length - 1))
        else
          raise PatchError, "cannot traverse #{node.class}"
        end
      end

      def array_index(token, max)
        unless token.is_a?(String) && token.match?(/\A(0|[1-9]\d*)\z/)
          raise PatchError, "invalid array index: #{token.inspect}"
        end
        index = Integer(token, 10)
        if index > max
          raise PatchError, "array index out of bounds: #{token.inspect}"
        end
        index
      end

      def deep_copy(value)
        case value
        when Hash
          value.each_with_object({}) { |(key, child), hash| hash[key] = deep_copy(child) }
        when Array
          value.map { |child| deep_copy(child) }
        else
          value
        end
      end
    end
  end
end
