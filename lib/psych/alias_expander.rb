# frozen_string_literal: true
require_relative 'exception'

module Psych
  # Expand YAML aliases into independent AST nodes before Ruby values are
  # constructed.
  class AliasExpander
    # Maximum number of scalar and container nodes produced by expansion.
    DEFAULT_MAX_EXPANDED_NODES = 1_000_000

    # Maximum total byte size of scalar values produced by expansion.
    DEFAULT_MAX_EXPANDED_BYTES = 1_048_576

    def self.expand(node, **options)
      new(**options).expand(node)
    end
    NODE_LIMIT_OPTIONS = %i[
      max_expanded_nodes max_expansion_nodes max_nodes
    ].freeze
    BYTE_LIMIT_OPTIONS = %i[
      max_expanded_bytes max_expansion_bytes max_scalar_bytes
      max_string_bytes max_bytes max_size
    ].freeze

    def initialize(**limit_options)
      @max_expanded_nodes = extract_limit(
        limit_options, NODE_LIMIT_OPTIONS, :max_expanded_nodes,
        DEFAULT_MAX_EXPANDED_NODES
      )
      @max_expanded_bytes = extract_limit(
        limit_options, BYTE_LIMIT_OPTIONS, :max_expanded_bytes,
        DEFAULT_MAX_EXPANDED_BYTES
      )
      known_options = NODE_LIMIT_OPTIONS + BYTE_LIMIT_OPTIONS
      unknown_options = limit_options.keys - known_options
      unless unknown_options.empty?
        raise ArgumentError, "unknown keyword: #{unknown_options.first}"
      end
    end

    # Validate and expand +node+.
    def expand node
      @alias_targets = {}
      @dependencies = Hash.new { |hash, key| hash[key] = [] }
      @container_nodes = {}

      collect(node, {}, [])
      detect_cycles!
      @costs = {}
      cost(node)
      expand_node(node)
    end

    private

    def extract_limit options, names, default_name, default
      specified = options.keys & names
      if specified.length > 1
        raise ArgumentError, "specify only one of #{names.join(', ')}"
      end

      name = specified.first || default_name
      validate_limit(options.fetch(name, default), name)
    end

    def validate_limit value, name
      return nil if value.nil?

      value = Integer(value)
      raise ArgumentError, "#{name} must be non-negative" if value < 0

      value
    end

    def collect node, anchors, containers
      case node
      when Nodes::Document
        collect_children(node, anchors.dup, containers)
      when Nodes::Stream
        node.children.each { |child| collect(child, {}, containers) }
      when Nodes::Alias
        target = anchors.fetch(node.anchor) { raise AnchorNotDefined, node.anchor }
        @alias_targets[node.object_id] = target
        if containers.last && (target.is_a?(Nodes::Sequence) || target.is_a?(Nodes::Mapping))
          @dependencies[containers.last.object_id] << target
        end
      when Nodes::Scalar
        anchors[node.anchor] = node if node.anchor
      when Nodes::Sequence, Nodes::Mapping
        anchors[node.anchor] = node if node.anchor
        @container_nodes[node.object_id] = node
        @dependencies[containers.last.object_id] << node if containers.last
        collect_children(node, anchors, containers + [node])
      end
    end

    def collect_children node, anchors, containers
      node.children.each { |child| collect(child, anchors, containers) }
    end

    def detect_cycles!
      visited = {}
      @container_nodes.each_value do |node|
        visit_cycle(node, visited)
      end
    end

    def visit_cycle node, visited, stack = {}
      return unless node.is_a?(Nodes::Sequence) || node.is_a?(Nodes::Mapping)

      if stack.key?(node.object_id)
        raise AliasCycle, node.anchor
      end
      return if visited.key?(node.object_id)

      visited[node.object_id] = true
      stack[node.object_id] = node
      @dependencies[node.object_id].each do |dependency|
        visit_cycle(dependency, visited, stack)
      end
      stack.delete(node.object_id)
    end

    def cost node
      @costs[node.object_id] ||= begin
        nodes = 0
        bytes = 0

        case node
        when Nodes::Alias
          nodes, bytes = cost(@alias_targets.fetch(node.object_id))
        when Nodes::Scalar
          nodes = 1
          bytes = node.value.is_a?(String) ? node.value.bytesize : 0
        when Nodes::Sequence, Nodes::Mapping
          nodes = 1
          node.children.each do |child|
            child_nodes, child_bytes = cost(child)
            nodes = add_cost(nodes, child_nodes, @max_expanded_nodes, "expanded nodes")
            bytes = add_cost(bytes, child_bytes, @max_expanded_bytes, "expanded bytes")
          end
        else
          node.children.each do |child|
            child_nodes, child_bytes = cost(child)
            nodes = add_cost(nodes, child_nodes, @max_expanded_nodes, "expanded nodes")
            bytes = add_cost(bytes, child_bytes, @max_expanded_bytes, "expanded bytes")
          end
        end

        check_cost(nodes, @max_expanded_nodes, "expanded nodes")
        check_cost(bytes, @max_expanded_bytes, "expanded bytes")
        [nodes, bytes]
      end
    end

    def add_cost left, right, limit, description
      result = left + right
      check_cost(result, limit, description)
      result
    end

    def check_cost value, limit, description
      return unless limit && value > limit

      raise AliasExpansionLimit, "Alias expansion exceeded #{limit} #{description}"
    end

    def expand_node node
      case node
      when Nodes::Alias
        expand_node(@alias_targets.fetch(node.object_id))
      when Nodes::Scalar
        copy = node.dup
        copy.anchor = nil
        copy.value = node.value.dup if node.value
        copy
      when Nodes::Sequence
        copy_container(node, node.class.new(nil, node.tag, node.implicit, node.style))
      when Nodes::Mapping
        copy_container(node, node.class.new(nil, node.tag, node.implicit, node.style))
      when Nodes::Document
        copy = node.class.new(node.version, node.tag_directives, node.implicit)
        copy.implicit_end = node.implicit_end
        copy_location(node, copy)
        copy.children.concat(node.children.map { |child| expand_node(child) })
        copy
      when Nodes::Stream
        copy = node.class.new(node.encoding)
        copy_location(node, copy)
        copy.children.concat(node.children.map { |child| expand_node(child) })
        copy
      else
        node.dup
      end
    end

    def copy_container node, copy
      copy_location(node, copy)
      copy.children.concat(node.children.map { |child| expand_node(child) })
      copy
    end

    def copy_location source, destination
      destination.start_line = source.start_line
      destination.start_column = source.start_column
      destination.end_line = source.end_line
      destination.end_column = source.end_column
    end
  end
end
