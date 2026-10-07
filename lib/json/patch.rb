# frozen_string_literal: true

require 'json'

class JSON::Patch
  class Error < JSON::JSONError; end
  class InvalidPatchError < Error; end

  Conflict = Struct.new(:operation, :path, :from, :code, :message) do
    def to_h
      {
        operation: operation,
        path: path,
        from: from,
        code: code,
        message: message
      }.reject { |_, value| value.nil? }
    end
  end

  Result = Struct.new(:patch, :conflicts) do
    def success?
      conflicts.empty?
    end

    def conflict?
      !success?
    end

    def to_h
      {
        patch: patch,
        conflicts: conflicts.map(&:to_h),
        success: success?
      }
    end
  end

  SUPPORTED_OPERATIONS = %w[add remove replace move copy test].freeze

  def self.apply(document, patch)
    relocator = allocate
    relocator.send(:initialize_application)
    root = Node.from_value(document, relocator.send(:counter))
    result = relocator.send(:apply_patch!, root, patch, false)
    result.to_value
  end

  def self.relocate(document, first_patch, second_patch)
    new(document, first_patch).relocate(second_patch)
  end

  def initialize(document, first_patch)
    @counter = IdCounter.new
    @changed_ids = {}
    @deleted_by_p_ids = {}
    @replacement_ids = {}

    @baseline = Node.from_value(document, @counter)
    @post_patch = apply_patch!(@baseline.clone_tree, first_patch, true)
    collect_provenance!(@post_patch)
  end

  def relocate(second_patch)
    raise InvalidPatchError, 'patch must be an array' unless Array === second_patch

    @source = @baseline.clone_tree
    @target = @post_patch.clone_tree
    @id_map = {}
    relocated = []
    @conflicts = []

    second_patch.each_with_index do |operation, index|
      validate_operation!(operation, index)
      transformed = transform_operation(operation, index)
      break unless transformed

      relocated << transformed
    end

    Result.new(@conflicts.empty? ? relocated : [], @conflicts)
  end

  private

  def initialize_application
    @counter = IdCounter.new
  end

  def counter
    @counter
  end

  def apply_patch!(root, patch, track_changes)
    raise InvalidPatchError, 'patch must be an array' unless Array === patch

    patch.each_with_index do |operation, index|
      validate_operation!(operation, index)
      result = apply_one!(root, operation, track_changes)
      root = result if result
    end
    root
  end

  def validate_operation!(operation, index = nil)
    unless Hash === operation
      raise InvalidPatchError, error_prefix(index) + 'operation must be an object'
    end

    name = operation['op']
    unless SUPPORTED_OPERATIONS.include?(name)
      raise InvalidPatchError, error_prefix(index) + "unsupported operation #{name.inspect}"
    end
    unless String === operation['path']
      raise InvalidPatchError, error_prefix(index) + 'path must be a JSON Pointer string'
    end
    if name == 'move' || name == 'copy'
      unless String === operation['from']
        raise InvalidPatchError, error_prefix(index) + 'from must be a JSON Pointer string'
      end
    end
    if %w[add replace test].include?(name) && !operation.key?('value')
      raise InvalidPatchError, error_prefix(index) + 'value is required'
    end
  end

  def error_prefix(index)
    index.nil? ? '' : "operation #{index}: "
  end

  def apply_one!(root, operation, track_changes)
    name = operation['op']
    path_tokens = parse_pointer!(operation['path'])

    case name
    when 'add'
      value_node = Node.from_value(operation['value'], @counter)
      mark_inserted!(value_node) if track_changes
      return value_node if path_tokens.empty?
      insert!(root, path_tokens, value_node)
      nil
    when 'remove'
      node = resolve!(root, path_tokens)
      raise InvalidPatchError, 'the root document cannot be removed' if node.equal?(root)
      mark_deleted_by_p!(node) if track_changes
      delete!(root, path_tokens)
      nil
    when 'replace'
      old_node = resolve!(root, path_tokens)
      value_node = Node.from_value(operation['value'], @counter)
      mark_inserted!(value_node) if track_changes
      mark_deleted_by_p!(old_node) if track_changes
      return value_node if path_tokens.empty?
      replace!(root, path_tokens, value_node)
      @replacement_ids[old_node.id] = value_node.id if track_changes
      nil
    when 'move'
      from_tokens = parse_pointer!(operation['from'])
      if proper_prefix?(from_tokens, path_tokens)
        raise InvalidPatchError, 'cannot move a path to one of its descendants'
      end
      source = resolve!(root, from_tokens)
      return nil if from_tokens == path_tokens

      delete!(root, from_tokens)
      return source if path_tokens.empty?
      insert!(root, path_tokens, source)
      nil
    when 'copy'
      source = resolve!(root, parse_pointer!(operation['from']))
      value_node = source.clone_tree(counter: @counter, new_ids: true)
      mark_inserted!(value_node) if track_changes
      return value_node if path_tokens.empty?
      insert!(root, path_tokens, value_node)
      nil
    when 'test'
      node = resolve!(root, path_tokens)
      unless values_equal?(node.to_value, operation['value'])
        raise InvalidPatchError, 'test operation failed'
      end
      nil
    end
  end

  def parse_pointer!(pointer)
    raise InvalidPatchError, 'JSON Pointer must be a string' unless String === pointer
    return [] if pointer.empty?
    raise InvalidPatchError, "invalid JSON Pointer #{pointer.inspect}" unless pointer.start_with?('/')

    pointer.split('/', -1).drop(1).map do |token|
      unless token.match?(/\A(?:[^~]|~[01])*\z/)
        raise InvalidPatchError, "invalid JSON Pointer escape in #{pointer.inspect}"
      end

      token.gsub('~1', '/').gsub('~0', '~')
    end
  end

  def resolve(root, tokens)
    node = root
    tokens.each do |token|
      return nil unless node.container?

      if node.array?
        index = array_index(token)
        return nil if index.nil?

        node = node.children[index]
      else
        node = node.children[token.to_s]
      end
      return nil if node.nil?
    end
    node
  end

  def resolve!(root, tokens)
    node = resolve(root, tokens)
    raise InvalidPatchError, "JSON Pointer #{pointer_for(tokens).inspect} does not exist" if node.nil?
    node
  end

  def pointer_for(tokens)
    return '' if tokens.empty?

    '/' + tokens.map { |token| token.to_s.gsub('~', '~0').gsub('/', '~1') }.join('/')
  end

  def insert!(root, tokens, node)
    parent_tokens = tokens[0...-1]
    parent = parent_tokens.empty? ? root : resolve!(root, parent_tokens)
    token = tokens.last
    raise InvalidPatchError, 'target is not a container' unless parent.container?
    parent.insert_child!(token, node)
  end

  def replace!(root, tokens, node)
    if tokens.empty?
      raise InvalidPatchError, 'internal error: root replacement must return a new root'
    end

    parent_tokens = tokens[0...-1]
    parent = parent_tokens.empty? ? root : resolve!(root, parent_tokens)
    token = tokens.last
    raise InvalidPatchError, 'target is not a container' unless parent.container?
    resolve!(root, tokens)
    parent.delete_child!(token)
    parent.insert_child!(token, node)
  end

  def delete!(root, tokens)
    parent_tokens = tokens[0...-1]
    parent = parent_tokens.empty? ? root : resolve!(root, parent_tokens)
    parent.delete_child!(tokens.last)
  end

  def array_index(token)
    return nil unless token.is_a?(String) && token.match?(/\A(?:0|[1-9]\d*)\z/)

    token.to_i
  end

  def mark_inserted!(node)
    node.changed = true
    node.each_child { |_, child| mark_inserted!(child) }
  end

  def mark_deleted_by_p!(node)
    @deleted_by_p_ids[node.id] = true
    return unless node.container?

    node.each_child { |_, child| mark_deleted_by_p!(child) }
  end

  def collect_provenance!(node)
    @changed_ids[node.id] = true if node.changed
    node.each_child { |_, child| collect_provenance!(child) }
  end

  def values_equal?(actual, expected)
    actual == expected
  end

  def proper_prefix?(prefix, tokens)
    tokens.length > prefix.length && tokens[0, prefix.length] == prefix
  end

  def transform_operation(operation, index)
    name = operation['op']
    path = operation['path']
    tokens = parse_pointer!(path)

    transformed = operation.dup
    from_tokens = nil

    if name == 'move' || name == 'copy'
      from = operation['from']
      from_tokens = parse_pointer!(from)
      source = resolve(@source, from_tokens)
      target_source = source && find_target(source.id)
      ancestor = missing_ancestor_conflict(from_tokens)
      if source.nil?
        add_conflict(index, name, path, from, 'source_deleted',
                     'move or copy source was removed by the first patch')
      elsif ancestor
        add_conflict(index, name, path, from, ancestor[0], ancestor[1])
      elsif target_source.nil? || !node_within?(target_source, @target)
        add_conflict(index, name, path, from, 'source_deleted',
                     'move or copy source was removed by the first patch')
      elsif subtree_changed?(target_source)
        add_conflict(index, name, path, from, 'source_changed',
                     'move or copy source was changed by the first patch')
      end
    end

    case name
    when 'add'
      target_path = map_add_path(tokens, index, operation)
    when 'replace', 'test'
      target_path = map_existing_path(tokens, name, index, operation)
    when 'remove'
      target_path = map_existing_path(tokens, name, index, operation)
    when 'move'
      if !from_tokens.nil? && proper_prefix?(from_tokens, tokens)
        add_conflict(index, name, path, operation['from'], 'invalid_operation',
                     'cannot move a path to one of its descendants')
      elsif from_tokens == tokens
        transformed['from'] = from
      end
      unless from_tokens == tokens
        target_path = map_move_path(tokens, from_tokens, index, operation)
      end
    when 'copy'
      target_path = map_copy_path(tokens, from_tokens, index, operation)
    end

    transformed['path'] = target_path
    if from_tokens && name == 'move' && from_tokens != tokens
      source = resolve(@source, from_tokens)
      target_source = source && find_target(source.id)
      transformed['from'] =
        if target_source && node_within?(target_source, @target)
          node_path(target_source)
        else
          operation['from']
        end
    elsif from_tokens && name == 'copy'
      source = resolve(@source, from_tokens)
      target_source = source && find_target(source.id)
      transformed['from'] =
        if target_source && node_within?(target_source, @target)
          node_path(target_source)
        else
          operation['from']
        end
    end

    return nil if @conflicts.any? { |conflict| conflict.operation == index }

    result = apply_operation!(@source, operation)
    @source = result if result
    result = apply_operation!(@target, transformed)
    @target = result if result
    remember_mappings!(operation, transformed)
    transformed
  rescue InvalidPatchError => error
    add_conflict(index, name, path, operation.is_a?(Hash) ? operation['from'] : nil,
                 'invalid_operation', error.message)
    nil
  end

  def map_existing_path(tokens, name, index, operation)
    node = resolve(@source, tokens)
    ancestor = missing_ancestor_conflict(tokens)
    if node.nil?
      add_conflict(index, name, operation['path'], nil, 'target_deleted',
                   'target path was removed by the first patch')
      return operation['path']
    elsif ancestor
      target = find_target(node.id)
      add_conflict(index, name, operation['path'], nil, ancestor[0], ancestor[1])
      return target && node_within?(target, @target) ? node_path(target) : operation['path']
    end

    target = find_target(node.id)
    if target.nil? || !node_within?(target, @target)
      add_conflict(index, name, operation['path'], nil, 'target_deleted',
                   'target path was removed by the first patch')
      return operation['path']
    elsif subtree_changed?(target)
      add_conflict(index, name, operation['path'], nil, 'target_changed',
                   'target value was changed by the first patch')
      return operation['path']
    end
    node_path(target)
  end

  def map_add_path(tokens, index, operation)
    map_destination_path(tokens, 'add', index, operation, nil)
  end

  def map_move_path(tokens, from_tokens, index, operation)
    return operation['path'] if from_tokens == tokens

    map_destination_path(tokens, 'move', index, operation, operation['from'])
  end

  def map_copy_path(tokens, from_tokens, index, operation)
    map_destination_path(tokens, 'copy', index, operation, operation['from'])
  end

  def map_destination_path(tokens, name, index, operation, from)
    if tokens.empty?
      if subtree_changed?(@target)
        add_conflict(index, name, operation['path'], from, 'target_changed',
                     'root document was changed by the first patch')
      end
      return ''
    end

    source_parent = resolve(@source, tokens[0...-1])
    ancestor = missing_ancestor_conflict(tokens[0...-1], true)

    if ancestor
      add_conflict(index, name, operation['path'], from, ancestor[0], ancestor[1])
      return operation['path']
    elsif source_parent.nil?
      add_conflict(index, name, operation['path'], from, 'ancestor_deleted',
                   'destination parent was removed by the first patch')
      return operation['path']
    end
    target_parent = find_target(source_parent.id)
    if target_parent.nil? || !node_within?(target_parent, @target)
      add_conflict(index, name, operation['path'], from, 'ancestor_deleted',
                   'destination parent was removed by the first patch')
      return operation['path']
    end
    if changed?(target_parent)
      add_conflict(index, name, operation['path'], from, 'ancestor_changed',
                   'destination parent was replaced by the first patch')
    end
    token = tokens.last
    if target_parent.array?
      map_array_insertion(tokens, target_parent, name, index, operation, from)
    else
      map_object_insertion(tokens, target_parent, token, name, index, operation, from)
    end
  end

  def map_object_insertion(tokens, target_parent, token, name, index, operation, from)
    existing = resolve(@source, tokens)
    target_occupied = target_parent.children[token]

    if existing
      target_node = find_target(existing.id)
      if target_node.nil?
        add_conflict(index, name, operation['path'], from, 'target_deleted',
                     'replaced target was removed by the first patch')
      elsif subtree_changed?(target_node)
        add_conflict(index, name, operation['path'], from, 'target_changed',
                     'same value or target was changed by the first patch')
      end
    elsif target_occupied
      add_conflict(index, name, operation['path'], from, 'target_occupied',
                   'object member was added by the first patch')
    end

    pointer_for([*node_path_tokens(target_parent), token])
  end

  def map_array_insertion(tokens, _target_parent, name, index, operation, from)
    source_array = resolve(@source, tokens[0...-1])
    target_array = find_target(source_array.id)
    token = tokens.last
    source_index = token == '-' ? source_array.children.length : array_index(token)
    if source_index.nil? || source_index > source_array.children.length
      raise InvalidPatchError, "array index #{token.inspect} is outside the array"
    end

    moving_id = moving_source_id(operation)
    predecessor, successor = array_anchors(source_array, source_index, moving_id, target_array)
    target_predecessor = predecessor
    target_successor = successor

    target_index = array_target_index(target_array, target_predecessor, target_successor)
    if target_predecessor && target_successor
      predecessor_index = target_array.children.index(target_predecessor)
      successor_index = target_array.children.index(target_successor)
      if successor_index <= predecessor_index
        add_conflict(index, name, operation['path'], from, 'array_reordered',
                     'array insertion anchors were reordered by the first patch')
      end
    end

    pointer_for([*node_path_tokens(target_array), target_index.to_s])
  end

  def moving_source_id(operation)
    name = operation['op']
    return nil unless name == 'move'

    source = resolve(@source, parse_pointer!(operation['from']))
    source&.id
  end

  def array_anchors(array, index, moving_id, target_array)
    predecessor = nil
    (index - 1).downto(0) do |candidate_index|
      candidate = array.children[candidate_index]
      next if candidate.id == moving_id || candidate.id == mapped_id(moving_id)

      target_candidate = find_target(candidate.id)
      next unless target_candidate && array_contains?(target_array, target_candidate)

      predecessor = target_candidate
      break
    end

    successor = nil
    (index...array.children.length).each do |candidate_index|
      candidate = array.children[candidate_index]
      next if candidate.id == moving_id || candidate.id == mapped_id(moving_id)

      target_candidate = find_target(candidate.id)
      next unless target_candidate && array_contains?(target_array, target_candidate)
      next if target_candidate.id == mapped_id(moving_id)

      successor = target_candidate
      break
    end
    [predecessor, successor]
  end

  def array_contains?(array, node)
    array.children.any? { |candidate| candidate.equal?(node) }
  end

  def mapped_id(id)
    id && (@id_map[id] || id)
  end

  def array_target_index(array, predecessor, successor)
    return array.children.length if predecessor.nil? && successor.nil?

    if predecessor
      array.children.index(predecessor) + 1
    else
      array.children.index(successor)
    end
  end

  def missing_ancestor_conflict(tokens, include_self = false)
    last_length = include_self ? tokens.length : tokens.length - 1
    (0...last_length).each do |length|
      prefix = tokens[0..length]
      source_node = resolve(@source, prefix)
      next if source_node.nil?
      target_node = find_target(source_node.id)
      next unless target_node.nil? || !node_within?(target_node, @target)

      replacement = @replacement_ids[source_node.id]
      next if replacement && find_by_id(@target, replacement)

      if @deleted_by_p_ids.key?(source_node.id)
        return ['ancestor_deleted', 'ancestor path was removed by the first patch']
      end
    end
    nil
  end

  def node_within?(node, ancestor)
    current = node
    while current
      return true if current.equal?(ancestor)

      current = current.parent
    end
    false
  end

  def changed?(node)
    @changed_ids.key?(node.id)
  end

  def subtree_changed?(node)
    return false if node.nil?
    return true if @changed_ids.key?(node.id)
    return false unless node.container?

    node.each_child do |_, child|
      return true if subtree_changed?(child)
    end
    false
  end

  def apply_operation!(root, operation)
    validate_operation!(operation)
    apply_one!(root, operation, false)
  end

  def find_target(id)
    mapped = @id_map[id] || @replacement_ids[id]
    find_by_id(@target, mapped || id)
  end

  def find_by_id(node, id)
    return node if node.id == id
    return nil unless node.container?

    node.each_child do |_, child|
      found = find_by_id(child, id)
      return found if found
    end
    nil
  end

  def node_path(node)
    pointer_for(node_path_tokens(node))
  end

  def node_path_tokens(node)
    tokens = []
    while node.parent
      tokens.unshift(node.key.to_s)
      node = node.parent
    end
    tokens
  end

  def remember_mappings!(operation, transformed)
    name = operation['op']

    case name
    when 'add'
      source_node = resolve!(@source, parse_pointer!(operation['path']))
      target_node = resolve!(@target, parse_pointer!(transformed['path']))
      map_tree!(source_node, target_node)
      map_parent_container!(operation, transformed)
    when 'replace'
      source_node = resolve!(@source, parse_pointer!(operation['path']))
      target_node = resolve!(@target, parse_pointer!(transformed['path']))
      map_tree!(source_node, target_node)
      map_parent_container!(operation, transformed)
    when 'copy'
      source_node = resolve!(@source, parse_pointer!(operation['path']))
      target_node = resolve!(@target, parse_pointer!(transformed['path']))
      map_tree!(source_node, target_node)
      map_parent_container!(operation, transformed)
    when 'move'
      return if operation['from'] == operation['path']

      source_node = resolve(@source, parse_pointer!(operation['path']))
      target_node = resolve(@target, parse_pointer!(transformed['path']))
      map_existing_tree!(source_node, target_node) if source_node && target_node
      map_containers_after_move!(operation, transformed)
      map_parent_container!(operation, transformed)
    when 'remove'
      map_parent_container!(operation, transformed)
    end
  end

  def map_tree!(source, target)
    @id_map[source.id] = target.id
    return unless source.container? && target.container?

    if source.array?
      source.children.each_with_index do |source_child, index|
        map_tree!(source_child, target.children[index])
      end
    else
      source.children.each do |key, source_child|
        target_child = target.children[key]
        map_tree!(source_child, target_child) if target_child
      end
    end
  end

  def map_existing_tree!(source, target)
    @id_map[source.id] = target.id
    return unless source.container? && target.container?

    if source.array?
      source.children.each do |source_child|
        target_child = find_by_id(target, @id_map[source_child.id] || source_child.id)
        map_existing_tree!(source_child, target_child) if target_child
      end
    else
      source.children.each do |_, source_child|
        target_child = find_by_id(target, @id_map[source_child.id] || source_child.id)
        map_existing_tree!(source_child, target_child) if target_child
      end
    end
  end

  def map_containers_after_move!(operation, transformed)
    from_tokens = parse_pointer!(operation['from'])
    target_from_tokens = parse_pointer!(transformed['from'])
    map_descendant_containers!(@source, from_tokens, @target, target_from_tokens)
  end

  def map_parent_container!(operation, transformed)
    tokens = parse_pointer!(operation['path'])
    transformed_tokens = parse_pointer!(transformed['path'])
    return if tokens.empty?

    source_parent = resolve(@source, tokens[0...-1])
    target_parent = resolve(@target, transformed_tokens[0...-1])
    return unless source_parent && target_parent && source_parent.array?

    @id_map[source_parent.id] = target_parent.id
  end

  def map_descendant_containers!(source, source_tokens, target, target_tokens)
    source.each_child do |token, source_child|
      child_source_tokens = [*source_tokens, token.to_s]
      child_target_tokens = [*target_tokens, token.to_s]
      target_child = resolve(target, child_target_tokens)
      source_moved_child = resolve(source, child_source_tokens)
      next unless source_moved_child && target_child

      @id_map[source_moved_child.id] = target_child.id
      map_descendant_containers!(source_moved_child, child_source_tokens,
                                 target_child, child_target_tokens)
    end
  end

  def add_conflict(index, operation, path, from, code, message)
    @conflicts << Conflict.new(index, path, from, code, message)
  end

  class IdCounter
    def initialize
      @next = 0
    end

    def next_id
      id = @next
      @next += 1
      id
    end
  end

  class Node
    attr_accessor :parent, :key, :id, :changed
    attr_reader :type, :value, :children

    def self.from_value(value, counter)
      return value if value.is_a?(Node)

      case value
      when Array
        node = new(:array, nil, [], counter.next_id)
        value.each do |original_child|
          child = from_value(deep_copy_value(original_child), counter)
          node.children << child
          child.parent = node
          child.key = node.children.length - 1
        end
        node
      when Hash
        node = new(:object, nil, {}, counter.next_id)
        value.each do |raw_key, original_child|
          token = raw_key.to_s
          child = from_value(deep_copy_value(original_child), counter)
          node.children[token] = child
          child.parent = node
          child.key = token
        end
        node
      else
        new(:scalar, deep_copy_value(value), nil, counter.next_id)
      end
    end

    def self.deep_copy_value(value)
      case value
      when Array
        value.map { |child| deep_copy_value(child) }
      when Hash
        value.each_with_object({}) do |(key, child), result|
          result[key.to_s] = deep_copy_value(child)
        end
      else
        value
      end
    end

    def initialize(type, value, children, id)
      @type = type
      @value = value
      @children = children
      @id = id
      @parent = nil
      @key = nil
      @changed = false
    end

    def array?
      type == :array
    end

    def object?
      type == :object
    end

    def container?
      array? || object?
    end

    def each_child(&block)
      return enum_for(:each_child) unless block_given?
      return unless container?

      if array?
        children.each_with_index do |child, index|
          block.call(index, child)
        end
      else
        children.each do |key, child|
          block.call(key, child)
        end
      end
    end

    def insert_child!(token, node)
      if array?
        index = insertion_index(token)
        if (index.nil? && token != '-') || index > children.length
          raise InvalidPatchError, "array index #{token.inspect} is outside the array"
        end

        children.insert(index, node)
        children.each_with_index { |child, child_index| child.key = child_index }
      else
        children.delete(token)
        children[token] = node
        node.key = token
      end
      node.parent = self
    end

    def delete_child!(token)
      if array?
        index = valid_array_index(token)
        if index.nil? || index >= children.length
          raise InvalidPatchError, "array index #{token.inspect} is outside the array"
        end

        node = children.delete_at(index)
        children.each_with_index { |child, child_index| child.key = child_index }
      else
        node = children.delete(token)
      end
      raise InvalidPatchError, 'object member does not exist' if node.nil?

      node.parent = nil
      node.key = nil
      node
    end

    def clone_tree(counter: nil, new_ids: false)
      cloned_children = array? ? [] : {}
      cloned = Node.new(type, value, cloned_children, new_ids ? counter.next_id : id)

      each_child do |token, child|
        clone = child.clone_tree(counter: counter, new_ids: new_ids)
        clone.parent = cloned
        clone.key = token
        if array?
          cloned.children << clone
        else
          cloned.children[token] = clone
        end
      end
      cloned
    end

    def to_value
      case type
      when :array
        children.map(&:to_value)
      when :object
        children.transform_values(&:to_value)
      else
        value
      end
    end

    def valid_array_index(token)
      return nil unless token.is_a?(String) && token.match?(/\A(?:0|[1-9]\d*)\z/)

      token.to_i
    end

    def insertion_index(token)
      return children.length if token == '-'

      valid_array_index(token)
    end
  end
end
