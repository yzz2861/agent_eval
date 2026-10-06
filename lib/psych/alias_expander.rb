# frozen_string_literal: true

module Psych
  ###
  # Expands YAML aliases in a parse tree into independent, deep copies of
  # the anchored nodes.  The resulting tree contains no Psych::Nodes::Alias
  # nodes, so loading it never shares Ruby objects between alias sites.
  #
  # Referencing the same anchor from multiple places is fine: every alias
  # site gets its own copy of the anchored subtree.  Only aliases that
  # would be expanded along their own expansion path (i.e. recursive
  # structures) are rejected with Psych::CircularAlias.
  #
  # Expansion happens on the AST before any Ruby objects are built, and is
  # bounded by two limits that only account for nodes produced by alias
  # expansion:
  #
  # [+max_nodes+]
  #   Maximum number of nodes produced by alias expansion.
  # [+max_string_bytes+]
  #   Maximum total bytes of scalar values produced by alias expansion.
  #
  # Exceeding either limit raises Psych::AliasExpansionLimitExceeded before
  # the corresponding Ruby objects are constructed.
  class AliasExpander
    DEFAULT_MAX_NODES = 100_000
    DEFAULT_MAX_STRING_BYTES = 1 << 20

    def self.expand node, max_nodes: DEFAULT_MAX_NODES, max_string_bytes: DEFAULT_MAX_STRING_BYTES
      new(max_nodes, max_string_bytes).expand node
    end

    def initialize max_nodes, max_string_bytes
      @max_nodes        = max_nodes
      @max_string_bytes = max_string_bytes
      @anchors          = {}
      @path             = []
      @expanding        = 0
      @nodes            = 0
      @string_bytes     = 0
    end

    def expand node
      expand_node node
    end

    private

    def expand_node node
      return expand_alias node if Nodes::Alias === node

      anchor = node.anchor if node.respond_to? :anchor
      unless anchor
        return expand_content node
      end

      @anchors[anchor] = node
      @path.push anchor
      begin
        expand_content node
      ensure
        @path.pop
      end
    end

    def expand_alias node
      target = @anchors.fetch(node.anchor) { raise AnchorNotDefined, node.anchor }
      if @path.include? node.anchor
        raise CircularAlias, node.anchor
      end

      @expanding += 1
      begin
        expand_node target
      ensure
        @expanding -= 1
      end
    end

    def expand_content node
      case node
      when Nodes::Scalar
        count_string node.value
        value = node.value
        value = value.dup if value
        count_node Nodes::Scalar.new(value, nil, node.tag, node.plain, node.quoted, node.style)
      when Nodes::Sequence
        expand_children node, Nodes::Sequence.new(nil, node.tag, node.implicit, node.style)
      when Nodes::Mapping
        expand_children node, Nodes::Mapping.new(nil, node.tag, node.implicit, node.style)
      when Nodes::Document
        copy = Nodes::Document.new node.version, node.tag_directives, node.implicit
        copy.implicit_end = node.implicit_end
        expand_children node, copy
      when Nodes::Stream
        expand_children node, Nodes::Stream.new(node.encoding)
      else
        raise ArgumentError, "cannot expand #{node.class}"
      end
    end

    def expand_children node, copy
      node.children.each do |child|
        copy.children << expand_node(child)
      end
      count_node copy
    end

    def count_node copy
      if @expanding > 0
        @nodes += 1
        if @nodes > @max_nodes
          raise AliasExpansionLimitExceeded,
            "alias expansion produced more than #{@max_nodes} nodes"
        end
      end
      copy
    end

    def count_string value
      return unless @expanding > 0 && value

      @string_bytes += value.bytesize
      if @string_bytes > @max_string_bytes
        raise AliasExpansionLimitExceeded,
          "alias expansion produced more than #{@max_string_bytes} bytes of string data"
      end
    end
  end
end
