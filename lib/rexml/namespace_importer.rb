# frozen_string_literal: true

require_relative "element"

module REXML
  class Element
    # :call-seq:
    #   import_subtree(source, mode: :copy, qname_attributes: nil) -> imported_element
    #
    # Imports the element subtree +source+ into this element, performing
    # namespace fixup so that the <em>expanded name</em> (namespace URI and
    # local name) of every element and attribute is preserved even when the
    # source and the destination bind the same prefix to different namespace
    # URIs.
    #
    # Returns the root element of the imported subtree. The imported subtree
    # becomes the last child of this element.
    #
    # === Ownership
    #
    # - <tt>mode: :copy</tt> (the default): +source+ and its document are left
    #   untouched; a deep copy is imported.
    # - <tt>mode: :move</tt>: +source+ is detached from its current parent (if
    #   any) and imported directly.
    #
    # === Namespace Fixup
    #
    # Namespace declarations needed by the imported content are added, and new
    # prefixes are allocated when a prefix already in scope at the insertion
    # point denotes a different namespace URI. An existing prefix is reused
    # when it already denotes the required URI.
    #
    # The default namespace is never used for unprefixed attributes, as
    # required by the XML Namespaces recommendation; an unprefixed attribute
    # therefore stays unprefixed and in no namespace.
    #
    # === QName-Valued Attributes
    #
    # Attribute values that themselves contain QNames (for example
    # <tt>xsi:type="p:Integer"</tt>) are rewritten <em>only</em> when the
    # attribute is listed in +qname_attributes+; colon-containing values of
    # other attributes are always copied verbatim. Each entry is either:
    #
    # - a Clark-notation attribute name, such as <tt>"{http://ns}type"</tt>
    #   (or simply <tt>"type"</tt> for an attribute in no namespace), which
    #   matches that attribute on any imported element; or
    # - a two-element array <tt>[element_clark_name, attribute_clark_name]</tt>,
    #   which matches only on elements with the given expanded name.
    #
    # Whitespace-separated QName lists (as used by
    # <tt>xsi:schemaLocation</tt>) are supported: only the tokens that contain
    # a colon are treated as QNames.
    #
    #   source_doc = REXML::Document.new('<r xmlns:p="http://example/a"><p:child p:id="1"/></r>')
    #   target_doc = REXML::Document.new('<r xmlns:p="http://example/OTHER"><host/></r>')
    #   host = target_doc.root.elements['host']
    #   imported = host.import_subtree(source_doc.root.elements['p:child'])
    #   imported.expanded_name                 # => "ns1:child"
    #   imported.namespace                     # => "http://example/a"
    #   imported.attribute('ns1:id').namespace # => "http://example/a"
    #
    def import_subtree(source, mode: :copy, qname_attributes: nil)
      NamespaceImporter.import(self, source, mode, qname_attributes)
    end
  end

  # Performs namespace-aware subtree import. This is an internal helper class
  # used by Element#import_subtree; the public entry point is that method.
  class NamespaceImporter # :nodoc: all
    XML_NAMESPACE_URI = "http://www.w3.org/XML/1998/namespace"

    def self.import(destination, source, mode, qname_attributes)
      unless source.is_a?(Element)
        raise ArgumentError, "import source must be an REXML::Element: #{source.inspect}"
      end
      unless destination.is_a?(Element)
        raise ArgumentError, "import destination must be an REXML::Element: #{destination.inspect}"
      end
      unless mode == :copy || mode == :move
        raise ArgumentError, "mode must be :copy or :move: #{mode.inspect}"
      end

      importer = new(qname_attributes)
      imported = importer.build_imported_root(source, mode,
                                              importer.destination_scope(destination))
      destination.add(imported)
      imported
    end

    def initialize(qname_attributes)
      @qname_matchers = build_qname_matchers(qname_attributes)
      @generated_prefix_count = 0
    end

    def build_imported_root(source, mode, destination_scope)
      root = mode == :copy ? source.deep_clone : source
      source_snapshots = {}
      capture_source(root, source_inherited_scope(source), source_snapshots)

      # The root's own declarations that still match the destination (or add
      # new bindings) are retained verbatim; conflicting ones (same prefix,
      # different URI at the destination) are dropped and re-allocated by the
      # fixup below.
      root_own = namespace_declarations(root)
      reusable_root_scope = {}
      root_own.each do |prefix, uri|
        existing = destination_scope[prefix]
        reusable_root_scope[prefix] = uri if existing.nil? || existing == uri
      end
      fixup(root, destination_scope, reusable_root_scope, source_snapshots)
      root
    end

    def destination_scope(destination)
      scope = destination._calculate_namespaces
      scope["xml"] ||= XML_NAMESPACE_URI
      scope
    end

    private

    # Snapshot the prefix-to-URI bindings in scope for each element of the
    # source subtree, before the subtree is detached or modified.
    def capture_source(element, inherited_scope, snapshots)
      scope = inherited_scope.merge(namespace_declarations(element))
      snapshots[element] = scope
      each_child_element(element) do |child|
        capture_source(child, scope, snapshots)
      end
    end

    # Rebuild the subtree so that the prefix used by every element and
    # attribute denotes the same namespace URI as it did in the source tree.
    def fixup(element, inherited_scope, retained_scope, source_snapshots)
      source_scope = source_snapshots.fetch(element)
      local_bindings = {}
      # Bindings visible inside this element: inherited bindings, declarations
      # retained verbatim on the subtree root, and freshly emitted ones.
      visible_scope = inherited_scope.merge(retained_scope)
      prefix_for_uri = {}

      allocate_prefix = lambda do |uri|
        existing = prefix_for_uri[uri]
        next existing if existing

        prefix = reusable_prefix(uri, visible_scope, local_bindings, retained_scope)
        if prefix
          # Reusing an inherited or retained declaration: no new declaration
          # needs to be emitted on this element.
          prefix_for_uri[uri] = prefix
          next prefix
        end
        prefix = generate_prefix(visible_scope, local_bindings)
        local_bindings[prefix] = uri
        prefix_for_uri[uri] = prefix
        prefix
      end

      source_element_prefix = element.prefix
      source_element_uri = source_uri_for(source_scope, source_element_prefix)
      element_prefix =
        if source_element_prefix.empty?
          source_uri = source_scope["xmlns"] || ""
          target_uri = visible_scope["xmlns"] || ""
          source_uri == target_uri ? "" : allocate_prefix.call(source_uri)
        else
          allocate_prefix.call(source_element_uri)
        end

      # new expanded name => [value, source namespace URI of the attribute]
      new_attributes = {}
      element.attributes.each_attribute do |attribute|
        next if attribute.namespace_declaration?

        if attribute.prefix.empty?
          # Unprefixed attributes are never bound to the default namespace.
          new_attributes[attribute.name] = [attribute.value, ""]
        else
          source_uri = source_scope.fetch(attribute.prefix, nil)
          target_prefix = allocate_prefix.call(source_uri)
          new_attributes["#{target_prefix}:#{attribute.name}"] =
            [attribute.value, source_uri || ""]
        end
      end

      rewrite_qname_values(element, source_element_uri, new_attributes,
                           source_scope, allocate_prefix)
      apply_element(element, element_prefix, local_bindings, new_attributes)

      child_inherited_scope = inherited_scope.merge(retained_scope).merge(local_bindings)
      each_child_element(element) do |child|
        fixup(child, child_inherited_scope, {}, source_snapshots)
      end
    end

    # Returns the namespace URI a prefix denoted in the source. An empty
    # prefix denotes the default namespace. An unbound prefix has no URI.
    def source_uri_for(source_scope, prefix)
      prefix.empty? ? (source_scope["xmlns"] || "") : source_scope.fetch(prefix, nil)
    end

    # Reuse an existing prefix when it already denotes the needed URI and is
    # not shadowed on this element by a newly allocated declaration.
    def reusable_prefix(uri, visible_scope, local_bindings, _retained_scope)
      visible_scope.each do |prefix, existing_uri|
        next if prefix == "xmlns"
        next if local_bindings.key?(prefix)
        return prefix if existing_uri == uri
      end
      nil
    end

    def generate_prefix(destination_scope, local_bindings)
      loop do
        @generated_prefix_count += 1
        prefix = "ns#{@generated_prefix_count}"
        next if prefix == "xml" || prefix == "xmlns"
        next if destination_scope.key?(prefix)
        next if local_bindings.key?(prefix)
        return prefix
      end
    end

    def rewrite_qname_values(element, source_element_uri, new_attributes,
                             source_scope, allocate_prefix)
      return if @qname_matchers.empty?

      element_clark = clark_name(source_element_uri, element.name)
      new_attributes.each do |attribute_name, entry|
        value = entry[0]
        next unless value.is_a?(String) && value.include?(":")

        _prefix, local_name = split_name(attribute_name)
        attribute_clark = clark_name(entry[1], local_name)
        next unless qname_attribute?(element_clark, attribute_clark)

        entry[0] = rewrite_qname_value(value, source_scope, allocate_prefix)
      end
    end

    def rewrite_qname_value(value, source_scope, allocate_prefix)
      value.split(/[\t\n\r ]+/, -1).map do |token|
        next token if token.empty?
        prefix, local_name = split_name(token)
        if prefix
          uri = source_scope.fetch(prefix, nil)
          uri ? "#{allocate_prefix.call(uri)}:#{local_name}" : token
        else
          token
        end
      end.join(" ")
    end

    def apply_element(element, element_prefix, local_bindings, new_attributes)
      attributes = element.attributes
      attributes.each_key.to_a.each { |name| attributes.delete(name) }

      default_uri = local_bindings["xmlns"]
      attributes["xmlns"] = default_uri if default_uri
      local_bindings.each do |prefix, uri|
        next if prefix == "xmlns"
        next if prefix == "xml" && uri == XML_NAMESPACE_URI
        attributes["xmlns:#{prefix}"] = uri
      end

      new_attributes.each do |name, (value, _source_uri)|
        attributes[name] = value
      end

      return if element_prefix.empty?
      element.name = "#{element_prefix}:#{element.name}"
    end

    def qname_attribute?(element_clark, attribute_clark)
      @qname_matchers.any? do |matcher_element, matcher_attribute|
        matcher_attribute == attribute_clark &&
          (matcher_element.nil? || matcher_element == element_clark)
      end
    end

    def build_qname_matchers(qname_attributes)
      return [] if qname_attributes.nil?

      qname_attributes.map do |entry|
        case entry
        when Array
          unless entry.size == 2
            raise ArgumentError,
                  "qname_attributes array entry must be [element_name, attribute_name]: #{entry.inspect}"
          end
          [parse_clark_name(entry[0]), parse_clark_name(entry[1])]
        when String
          [nil, parse_clark_name(entry)]
        else
          raise ArgumentError,
                "qname_attributes entry must be a String or a 2-element Array: #{entry.inspect}"
        end
      end
    end

    # Validates a Clark-notation name ("{uri}local" or "local") and returns
    # it as the canonical Clark-notation string used internally.
    def parse_clark_name(value)
      unless value.is_a?(String)
        raise ArgumentError, "QName selector must be a String: #{value.inspect}"
      end

      if value.start_with?("{")
        close = value.index("}")
        local_name = close && value[(close + 1)..-1]
        if local_name.nil? || local_name.empty?
          raise ArgumentError, "malformed Clark notation: #{value.inspect}"
        end
        value
      else
        if value.empty? || value.include?(":")
          raise ArgumentError, "malformed Clark notation: #{value.inspect}"
        end
        value
      end
    end

    def clark_name(uri, local_name)
      uri && !uri.empty? ? "{#{uri}}#{local_name}" : local_name
    end

    def namespace_declarations(element)
      declarations = {}
      element.attributes.each_attribute do |attribute|
        next unless attribute.namespace_declaration?
        if attribute.prefix == "xmlns"
          declarations[attribute.name] = attribute.value
        else
          declarations["xmlns"] = attribute.value
        end
      end
      declarations
    end

    # Bindings inherited by the source subtree root from its ancestors.
    def source_inherited_scope(source)
      scope = source.parent ? source.parent._calculate_namespaces : {}
      scope["xml"] ||= XML_NAMESPACE_URI
      scope
    end

    def each_child_element(element, &block)
      element.each do |child|
        yield child if child.is_a?(Element) && !child.is_a?(Document)
      end
    end

    def split_name(name)
      match = Namespace::NAMESPLIT.match(name)
      match ? [match[1] || "", match[2]] : nil
    end
  end
end
