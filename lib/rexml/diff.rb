# frozen_string_literal: false

require_relative "document"

module REXML
  # \REXML::Diff compares two XML documents structurally and reports
  # their differences.
  #
  # The comparison is namespace-aware and order-sensitive:
  #
  # - Elements and attributes are matched by expanded name
  #   (namespace URI + local name), so renaming a namespace prefix or
  #   reordering attributes is not reported as a difference.
  #   Namespace declarations (+xmlns+, +xmlns:prefix+) are never
  #   reported as attribute differences.
  # - Child nodes are compared in document order.  Text nodes in mixed
  #   content are significant: their positions and exact values matter,
  #   and they are never trimmed before comparison.
  # - Comments are ignored unless option +comments+ is true.
  # - Neither document is modified.
  #
  # Each reported difference carries a stable node address (an
  # XPath-like path such as <tt>/root/{urn:x}item[2]/@id</tt>) plus the
  # before and after values.
  #
  # == Identity attributes
  #
  # When an element repeats under the same parent (for example several
  # +item+ entries in a configuration file), option
  # +identity_attributes+ tells the comparer how to pair the
  # repetitions across the two documents instead of pairing them
  # purely by position:
  #
  #   differences = REXML::Diff.compare(
  #     before, after,
  #     identity_attributes: {"item" => ["id"], "{urn:x}entry" => ["key"]},
  #   )
  #
  # Element names may be local names or <tt>{uri}local</tt> forms;
  # <tt>"*"</tt> applies the attributes to every element.  A plain
  # array of attribute names is shorthand for <tt>{"*" => names}</tt>.
  #
  # Elements matched by identity are compared with each other even if
  # they moved within their parent; elements without any of the
  # configured attributes fall back to positional matching.  If two
  # elements on the same side yield the same identity key, the match
  # is ambiguous and AmbiguousIdentityError is raised rather than
  # picking one arbitrarily.
  #
  # == Example
  #
  #   require "rexml/diff"
  #
  #   REXML::Diff.compare("<a x='1'/>", "<a x='2'/>")
  #   # => [#<struct REXML::Diff::Difference
  #   #      kind=:attribute_changed,
  #   #      path="/a/@x", before="1", after="2">]
  module Diff
    # A single structural difference between two documents.
    #
    # - +kind+: a Symbol such as +:attribute_changed+ or +:node_added+.
    # - +path+: stable address of the node.  For +:node_added+ it
    #   addresses the node in the right-hand (after) document;
    #   otherwise it addresses the node in the left-hand (before)
    #   document.
    # - +before+: value in the left-hand document, or +nil+.
    # - +after+: value in the right-hand document, or +nil+.
    Difference = Struct.new(:kind, :path, :before, :after) do
      def to_s
        "#{kind} at #{path}: #{before.inspect} -> #{after.inspect}"
      end
    end

    # Raised when identity attributes map two or more sibling elements
    # on the same side of the comparison to the same key, so the
    # elements cannot be paired unambiguously.
    class AmbiguousIdentityError < StandardError
    end

    # Compares +left+ and +right+ and returns an Array of Difference.
    #
    # Each of +left+ and +right+ may be an XML String, a
    # REXML::Document, or a REXML::Element.  See REXML::Diff for the
    # options.
    def self.compare(left, right, identity_attributes: nil, comments: false)
      comparer = Comparer.new(identity_attributes: identity_attributes,
                              comments: comments)
      comparer.compare(left, right)
    end

    # :stopdoc:
    class Comparer
      def initialize(identity_attributes:, comments:)
        @identity_any, @identity_by_name = normalize_identity(identity_attributes)
        @comments = comments
        @differences = []
      end

      def compare(left, right)
        left_root = resolve_root(left)
        right_root = resolve_root(right)
        compare_elements(left_root, right_root, "/" + name_segment(left_root))
        @differences
      end

      private

      def resolve_root(node)
        case node
        when String
          Document.new(node).root
        when Document
          node.root
        when Element
          node
        else
          raise ArgumentError,
                "expected an XML String, REXML::Document, or REXML::Element: " +
                node.inspect
        end or raise ArgumentError,
              "document has no root element"
      end

      def compare_elements(left, right, path)
        if element_key(left) != element_key(right)
          add(:element_name_changed, path,
              format_name(*element_key(left)),
              format_name(*element_key(right)))
        end
        compare_attributes(left, right, path)
        compare_children(left, right, path)
      end

      def compare_attributes(left, right, path)
        left_attributes = attribute_map(left)
        right_attributes = attribute_map(right)
        left_attributes.each do |key, value|
          if right_attributes.key?(key)
            if right_attributes[key] != value
              add(:attribute_changed, attribute_path(path, key),
                  value, right_attributes[key])
            end
          else
            add(:attribute_removed, attribute_path(path, key), value, nil)
          end
        end
        right_attributes.each do |key, value|
          unless left_attributes.key?(key)
            add(:attribute_added, attribute_path(path, key), nil, value)
          end
        end
      end

      def compare_children(left, right, path)
        left_children = annotated_children(left)
        right_children = annotated_children(right)
        if identity_matching?(left_children) || identity_matching?(right_children)
          compare_children_by_identity(left_children, right_children, path)
        else
          compare_sequence(left_children, right_children, path)
        end
      end

      def compare_children_by_identity(left_children, right_children, path)
        left_keyed, left_rest = partition_keyed(left_children)
        right_keyed, right_rest = partition_keyed(right_children)
        left_map = key_map(left_keyed)
        right_map = key_map(right_keyed)
        left_keyed.each do |key, node, segment|
          if right_map.key?(key)
            compare_elements(node, right_map[key][0], path + "/" + segment)
          else
            add(:node_removed, path + "/" + segment, describe(node), nil)
          end
        end
        right_keyed.each do |key, node, segment|
          unless left_map.key?(key)
            add(:node_added, path + "/" + segment, nil, describe(node))
          end
        end
        compare_sequence(left_rest, right_rest, path)
      end

      def compare_sequence(left_children, right_children, path)
        [left_children.size, right_children.size].max.times do |index|
          left_entry = left_children[index]
          right_entry = right_children[index]
          if left_entry && right_entry
            compare_pair(left_entry, right_entry, path)
          elsif left_entry
            add(:node_removed, path + "/" + left_entry[1],
                describe(left_entry[0]), nil)
          else
            add(:node_added, path + "/" + right_entry[1],
                nil, describe(right_entry[0]))
          end
        end
      end

      def compare_pair(left_entry, right_entry, path)
        left_node, left_segment = left_entry
        right_node, _right_segment = right_entry
        child_path = path + "/" + left_segment
        if left_node.is_a?(Element) && right_node.is_a?(Element)
          compare_elements(left_node, right_node, child_path)
        elsif left_node.is_a?(Text) && right_node.is_a?(Text)
          if left_node.value != right_node.value
            add(:text_changed, child_path, left_node.value, right_node.value)
          end
        elsif left_node.is_a?(Comment) && right_node.is_a?(Comment)
          if left_node.string != right_node.string
            add(:comment_changed, child_path, left_node.string, right_node.string)
          end
        else
          add(:node_type_changed, child_path,
              describe(left_node), describe(right_node))
        end
      end

      # Returns [[node, path_segment], ...] for the comparable children
      # of +element+, numbering siblings that share a node kind and
      # expanded name (1-based, XPath-style) so addresses stay stable.
      def annotated_children(element)
        children = element.children.select do |child|
          child.is_a?(Element) or
            child.is_a?(Text) or
            (@comments and child.is_a?(Comment))
        end
        totals = Hash.new(0)
        children.each {|child| totals[sort_key(child)] += 1}
        counts = Hash.new(0)
        children.map do |child|
          key = sort_key(child)
          counts[key] += 1
          segment = base_segment(child)
          segment += "[#{counts[key]}]" if totals[key] > 1
          [child, segment]
        end
      end

      def sort_key(node)
        case node
        when Element
          [:element, element_key(node)]
        when Comment
          [:comment]
        else
          [:text]
        end
      end

      def base_segment(node)
        case node
        when Element
          name_segment(node)
        when Comment
          "comment()"
        else
          "text()"
        end
      end

      def name_segment(element)
        format_name(*element_key(element))
      end

      def identity_matching?(annotated_children)
        return false if @identity_any.empty? && @identity_by_name.empty?
        annotated_children.any? do |node, _segment|
          node.is_a?(Element) && identity_key(node)
        end
      end

      def partition_keyed(annotated_children)
        keyed = []
        rest = []
        annotated_children.each do |node, segment|
          key = node.is_a?(Element) && identity_key(node)
          if key
            keyed << [key, node, segment]
          else
            rest << [node, segment]
          end
        end
        [keyed, rest]
      end

      def key_map(keyed_entries)
        map = {}
        keyed_entries.each do |key, node, segment|
          if map.key?(key)
            raise AmbiguousIdentityError,
                  "identity attributes #{key[1].inspect} are not unique " +
                  "for <#{format_name(*key[0])}> elements"
          end
          map[key] = [node, segment]
        end
        map
      end

      def identity_key(element)
        specs = @identity_any
        by_name = @identity_by_name[element_key(element)]
        specs = specs + by_name if by_name
        return nil if specs.empty?
        pairs = []
        specs.each do |attribute_key|
          value = attribute_value(element, attribute_key)
          pairs << [attribute_key, value] if value
        end
        pairs.empty? ? nil : [element_key(element), pairs]
      end

      def attribute_value(element, wanted_key)
        element.attributes.each_attribute do |attribute|
          next if namespace_declaration?(attribute)
          return attribute.value if attribute_key(attribute) == wanted_key
        end
        nil
      end

      def attribute_map(element)
        map = {}
        element.attributes.each_attribute do |attribute|
          next if namespace_declaration?(attribute)
          map[attribute_key(attribute)] = attribute.value
        end
        map
      end

      def namespace_declaration?(attribute)
        attribute.expanded_name == "xmlns" or
          attribute.expanded_name.start_with?("xmlns:")
      end

      def element_key(element)
        [normalize_uri(element.namespace), element.name]
      end

      def attribute_key(attribute)
        [normalize_uri(attribute.namespace), attribute.name]
      end

      def normalize_uri(uri)
        uri.nil? || uri.empty? ? nil : uri
      end

      def attribute_path(path, key)
        "#{path}/@#{format_name(*key)}"
      end

      def format_name(uri, local_name)
        uri ? "{#{uri}}#{local_name}" : local_name
      end

      def describe(node)
        case node
        when Element
          "<#{name_segment(node)}>"
        when Comment
          node.string
        else
          node.value
        end
      end

      def add(kind, path, before, after)
        @differences << Difference.new(kind, path, before, after)
      end

      def normalize_identity(config)
        any = []
        by_name = {}
        case config
        when nil
        when Array
          any = config.map {|name| parse_name(name)}
        when Hash
          config.each do |element_name, attribute_names|
            keys = Array(attribute_names).map {|name| parse_name(name)}
            if element_name == "*"
              any.concat(keys)
            else
              by_name[parse_name(element_name)] = keys
            end
          end
        else
          raise ArgumentError,
                "identity_attributes must be an Array or a Hash: " +
                config.inspect
        end
        [any, by_name]
      end

      def parse_name(name)
        name = name.to_s
        if name.start_with?("{")
          uri, local_name = name[1..].split("}", 2)
          [uri, local_name]
        else
          [nil, name]
        end
      end
    end
    # :startdoc:
  end
end
