# frozen_string_literal: true
require_relative "document"

module REXML
  # \REXML::Diff compares two XML documents (or elements) structurally
  # and reports the differences.
  #
  # The comparison is semantic rather than textual:
  #
  # - Elements and attributes are identified by their expanded name
  #   (namespace URI + local name), so renaming a namespace prefix or
  #   reordering attributes is not reported as a difference.
  # - Namespace declaration attributes (+xmlns+, +xmlns:foo+) are ignored.
  # - Child content is compared in document order.  Text nodes are
  #   significant: they are compared verbatim (never trimmed) and their
  #   position relative to sibling elements matters.
  # - Comments are ignored by default; pass <tt>comments: true</tt> to
  #   include them in the comparison.
  # - Processing instructions, the XML declaration and the doctype are
  #   not compared.
  #
  # The compared trees are never modified.
  #
  # == Usage
  #
  #   differences = REXML::Diff.compare(before_document, after_document)
  #   differences.each do |difference|
  #     puts difference
  #   end
  #
  #   REXML::Diff.identical?(before_document, after_document) # => false
  #
  # Each difference has a +kind+, a stable node +path+ (an XPath-like
  # address that uses expanded names, so it does not depend on namespace
  # prefixes), and the +before+/+after+ values.
  #
  # == Matching repeated sibling elements
  #
  # By default, sibling elements with the same expanded name are paired
  # by position.  When the documents contain repeated elements that may
  # be reordered, the caller can name identity attributes used to pair
  # them instead:
  #
  #   REXML::Diff.compare(a, b, identity_attributes: ["id"])
  #
  # Pairing by identity requires every element in a repeated group to
  # carry a distinct key.  If the keys collide (or are missing) so that
  # no unambiguous pairing exists, an +:ambiguous_match+ difference is
  # reported for the group and its elements are not paired arbitrarily.
  class Diff
    # A single structural difference between two XML trees.
    #
    # - +kind+: a Symbol such as +:element_added+, +:attribute_changed+,
    #   +:text_changed+, +:comment_removed+, +:content_order_changed+ or
    #   +:ambiguous_match+.
    # - +path+: a stable, prefix-independent node address, e.g.
    #   <tt>/config/server[2]/@port</tt>, <tt>/config/text()[1]</tt> or
    #   <tt>/{http://example.com/ns}config/item</tt>.
    # - +before+: the value in the first document (+nil+ for additions).
    # - +after+: the value in the second document (+nil+ for removals).
    class Difference
      attr_reader :kind, :path, :before, :after

      def initialize(kind, path, before, after)
        @kind = kind
        @path = path
        @before = before
        @after = after
      end

      def ==(other)
        other.kind_of?(Difference) and
          other.kind == kind and
          other.path == path and
          other.before == before and
          other.after == after
      end
      alias eql? ==

      def hash
        [kind, path, before, after].hash
      end

      def to_s
        "#{kind} at #{path}: #{format_value(before)} -> #{format_value(after)}"
      end

      private

      def format_value(value)
        value.nil? ? "(none)" : value.inspect
      end
    end

    class << self
      # Compares +left+ and +right+ (REXML::Document or REXML::Element
      # objects) and returns an Array of REXML::Diff::Difference.
      #
      # Options:
      # - +identity_attributes+: attribute local names used to pair
      #   repeated sibling elements instead of positional pairing.
      # - +comments+: when true, comment nodes participate in the
      #   comparison (default: false).
      def compare(left, right, identity_attributes: [], comments: false)
        new(identity_attributes: identity_attributes,
            comments: comments).compare(left, right)
      end

      # Returns true if +left+ and +right+ are structurally identical
      # under the same rules as ::compare.
      def identical?(left, right, **options)
        compare(left, right, **options).empty?
      end
    end

    def initialize(identity_attributes: [], comments: false)
      @identity_attributes = identity_attributes.map(&:to_s)
      @comments = comments
      @differences = []
    end

    # Compares +left+ and +right+ and returns the differences.
    def compare(left, right)
      @differences = []
      compare_roots(root_of(left), root_of(right))
      @differences
    end

    private

    def root_of(node)
      node.is_a?(Document) ? node.root : node
    end

    def compare_roots(left, right)
      if left.nil?
        add_difference(:element_added, root_path(right), nil, name_token(expanded_key(right)))
      elsif right.nil?
        add_difference(:element_removed, root_path(left), name_token(expanded_key(left)), nil)
      elsif expanded_key(left) != expanded_key(right)
        add_difference(:element_removed, root_path(left), name_token(expanded_key(left)), nil)
        add_difference(:element_added, root_path(right), nil, name_token(expanded_key(right)))
      else
        compare_element(left, right, root_path(left))
      end
    end

    def root_path(element)
      "/#{name_token(expanded_key(element))}"
    end

    def compare_element(left, right, path)
      compare_attributes(left, right, path)
      compare_children(left, right, path)
    end

    def compare_attributes(left, right, path)
      left_attributes = attribute_map(left)
      right_attributes = attribute_map(right)
      ordered_union(left_attributes.keys, right_attributes.keys).each do |key|
        attribute_path = "#{path}/@#{name_token(key)}"
        if not right_attributes.key?(key)
          add_difference(:attribute_removed, attribute_path, left_attributes[key], nil)
        elsif not left_attributes.key?(key)
          add_difference(:attribute_added, attribute_path, nil, right_attributes[key])
        elsif left_attributes[key] != right_attributes[key]
          add_difference(:attribute_changed, attribute_path,
                         left_attributes[key], right_attributes[key])
        end
      end
    end

    def compare_children(left, right, path)
      left_children = significant_children(left)
      right_children = significant_children(right)
      pairs = pair_elements(left_children, right_children, path)
      pairs.each do |left_element, right_element, child_path|
        compare_element(left_element, right_element, child_path)
      end
      compare_text_nodes(left_children, right_children, path)
      compare_comment_nodes(left_children, right_children, path) if @comments
      compare_content_order(left_children, right_children, pairs, path)
    end

    # Pairs the element children of the two nodes; reports additions,
    # removals and ambiguous groups.  Returns an Array of
    # [left_element, right_element, child_path] triples.
    def pair_elements(left_children, right_children, path)
      left_groups = group_elements(left_children)
      right_groups = group_elements(right_children)
      pairs = []
      ordered_union(left_groups.keys, right_groups.keys).each do |key|
        token = name_token(key)
        left_group = left_groups[key] || []
        right_group = right_groups[key] || []
        pair_group(left_group, right_group, token, path, pairs)
      end
      pairs
    end

    def pair_group(left_group, right_group, token, path, pairs)
      if left_group.size == 1 and right_group.size == 1
        pairs << [left_group[0], right_group[0],
                  child_path(path, token, 1, false)]
        return
      end
      if @identity_attributes.empty?
        pair_group_by_position(left_group, right_group, token, path, pairs)
      else
        pair_group_by_identity(left_group, right_group, token, path, pairs)
      end
    end

    def pair_group_by_position(left_group, right_group, token, path, pairs)
      left_group.each_with_index do |element, index|
        element_path = child_path(path, token, index + 1, left_group.size > 1)
        if index < right_group.size
          pairs << [element, right_group[index], element_path]
        else
          add_difference(:element_removed, element_path, token, nil)
        end
      end
      right_group.each_with_index do |element, index|
        next if index < left_group.size
        element_path = child_path(path, token, index + 1, right_group.size > 1)
        add_difference(:element_added, element_path, nil, token)
      end
    end

    def pair_group_by_identity(left_group, right_group, token, path, pairs)
      left_keys = left_group.map {|element| identity_key(element) }
      right_keys = right_group.map {|element| identity_key(element) }
      if ambiguous?(left_keys) or ambiguous?(right_keys)
        add_difference(:ambiguous_match, "#{path}/#{token}", left_keys, right_keys)
        return
      end
      right_index = {}
      right_group.each_with_index do |element, index|
        right_index[right_keys[index]] = element
      end
      left_group.each_with_index do |element, index|
        key = left_keys[index]
        element_path = child_path(path, token, index + 1, left_group.size > 1)
        if right_index.key?(key)
          pairs << [element, right_index[key], element_path]
        else
          add_difference(:element_removed, element_path, token, nil)
        end
      end
      right_group.each_with_index do |element, index|
        next if left_keys.include?(right_keys[index])
        element_path = child_path(path, token, index + 1, right_group.size > 1)
        add_difference(:element_added, element_path, nil, token)
      end
    end

    def compare_text_nodes(left_children, right_children, path)
      left_texts = left_children.select {|child| child.is_a?(Text) }
      right_texts = right_children.select {|child| child.is_a?(Text) }
      left_texts.each_with_index do |text, index|
        text_path = "#{path}/text()[#{index + 1}]"
        if index >= right_texts.size
          add_difference(:text_removed, text_path, text.value, nil)
        elsif text.value != right_texts[index].value
          add_difference(:text_changed, text_path,
                         text.value, right_texts[index].value)
        end
      end
      right_texts.each_with_index do |text, index|
        next if index < left_texts.size
        add_difference(:text_added, "#{path}/text()[#{index + 1}]", nil, text.value)
      end
    end

    def compare_comment_nodes(left_children, right_children, path)
      left_comments = left_children.select {|child| child.is_a?(Comment) }
      right_comments = right_children.select {|child| child.is_a?(Comment) }
      left_comments.each_with_index do |comment, index|
        comment_path = "#{path}/comment()[#{index + 1}]"
        if index >= right_comments.size
          add_difference(:comment_removed, comment_path, comment.to_s, nil)
        elsif comment.to_s != right_comments[index].to_s
          add_difference(:comment_changed, comment_path,
                         comment.to_s, right_comments[index].to_s)
        end
      end
      right_comments.each_with_index do |comment, index|
        next if index < left_comments.size
        add_difference(:comment_added, "#{path}/comment()[#{index + 1}]",
                       nil, comment.to_s)
      end
    end

    # Reports a difference when matched nodes appear in a different
    # relative order (e.g. text moved across a sibling element).
    # Element tokens carry no pairing information, so reordering
    # identity-matched siblings is not by itself a difference.
    def compare_content_order(left_children, right_children, pairs, path)
      paired = {}
      pairs.each do |left_element, right_element, _|
        paired[left_element] = paired[right_element] = true
      end
      paired_text_count = [
        left_children.count {|child| child.is_a?(Text) },
        right_children.count {|child| child.is_a?(Text) },
      ].min
      paired_comment_count = [
        left_children.count {|child| child.is_a?(Comment) },
        right_children.count {|child| child.is_a?(Comment) },
      ].min
      left_signature = content_signature(left_children, paired,
                                         paired_text_count, paired_comment_count)
      right_signature = content_signature(right_children, paired,
                                          paired_text_count, paired_comment_count)
      if left_signature != right_signature
        add_difference(:content_order_changed, path,
                       left_signature.join(" "), right_signature.join(" "))
      end
    end

    def content_signature(children, paired, paired_text_count, paired_comment_count)
      signature = []
      seen_text = 0
      seen_comment = 0
      children.each do |child|
        case child
        when Element
          signature << name_token(expanded_key(child)) if paired[child]
        when Text
          seen_text += 1
          signature << "text()" if seen_text <= paired_text_count
        when Comment
          seen_comment += 1
          if @comments and seen_comment <= paired_comment_count
            signature << "comment()"
          end
        end
      end
      signature
    end

    def significant_children(element)
      element.children.select do |child|
        child.is_a?(Element) or child.is_a?(Text) or
          (@comments and child.is_a?(Comment))
      end
    end

    def group_elements(children)
      groups = {}
      children.each do |child|
        next unless child.is_a?(Element)
        (groups[expanded_key(child)] ||= []) << child
      end
      groups
    end

    def attribute_map(element)
      map = {}
      element.attributes.each_attribute do |attribute|
        next if attribute.namespace_declaration?
        map[[attribute.namespace.to_s, attribute.name]] = attribute.value
      end
      map
    end

    def expanded_key(element)
      [element.namespace.to_s, element.name]
    end

    def identity_key(element)
      @identity_attributes.map do |name|
        attribute = element.attributes.each_attribute.find do |candidate|
          not candidate.namespace_declaration? and candidate.name == name
        end
        attribute&.value
      end
    end

    # A group can only be paired by identity when every key is fully
    # present and distinct; otherwise pairing would be arbitrary.
    def ambiguous?(keys)
      keys.any? {|key| key.include?(nil) } or keys.uniq.size != keys.size
    end

    def name_token(key)
      uri, local_name = key
      uri.empty? ? local_name : "{#{uri}}#{local_name}"
    end

    def child_path(parent_path, token, index, show_index)
      show_index ? "#{parent_path}/#{token}[#{index}]" : "#{parent_path}/#{token}"
    end

    def ordered_union(left_keys, right_keys)
      left_keys | right_keys
    end

    def add_difference(kind, path, before, after)
      @differences << Difference.new(kind, path, before, after)
    end
  end
end
