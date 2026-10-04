# frozen_string_literal: false

require_relative '../element'
require_relative '../text'
require_relative '../comment'
require_relative '../instruction'

module REXML
  module C14N
    # Exclusive XML Canonicalization version 1.0
    # ({https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/ W3C REC}).
    #
    # Unlike the pretty/default formatters, this writer produces canonical
    # bytes:
    #
    # - UTF-8 encoded output,
    # - namespace declarations are rendered only where they are visibly
    #   utilized (or forced in through the InclusiveNamespaces prefix list),
    # - the default namespace is cleared with +xmlns=""+ when an element in
    #   no namespace is reached through an ancestor default namespace,
    # - attributes are sorted by namespace URI and then local name,
    # - text and attribute values use canonical escapes, and
    # - comments may be included or omitted.
    #
    # The input tree is never modified.
    #
    #   require 'rexml/document'
    #   require 'rexml/c14n/exclusive'
    #
    #   document = REXML::Document.new(xml)
    #   REXML::C14N::Exclusive.new.canonicalize(document)
    #   REXML::C14N::Exclusive.new(true, ['foo']).canonicalize(subtree)
    class Exclusive
      # Canonical URI of the comment-free exclusive form.
      XMLNS_EXCLUSIVE = 'http://www.w3.org/2001/10/xml-exc-c14n#'

      # Canonical URI of the with-comments exclusive form.
      XMLNS_EXCLUSIVE_WITH_COMMENTS =
        'http://www.w3.org/2001/10/xml-exc-c14n#WithComments'

      # :call-seq:
      #   new(with_comments = false, inclusive_namespace_prefixes = nil)
      #
      # Creates a new writer.
      #
      # with_comments:: When +true+, comments in the input are emitted in the
      #                 output. Defaults to +false+.
      # inclusive_namespace_prefixes:: Array of prefixes that must be treated
      #                 inclusively, as with the +InclusiveNamespaces+ +PrefixList+
      #                 parameter. The string +"#default"+ refers to the default
      #                 namespace. Defaults to an empty list.
      def initialize(with_comments = false, inclusive_namespace_prefixes = nil)
        @with_comments = with_comments
        @inclusive_prefixes = {}
        Array(inclusive_namespace_prefixes).each do |prefix|
          prefix = '' if prefix == '#default'
          @inclusive_prefixes[prefix] = true
        end
      end

      # Returns whether comments are emitted.
      def with_comments?
        @with_comments
      end

      # Returns the InclusiveNamespaces prefix list (with +"#default"+
      # represented as the empty string).
      def inclusive_namespace_prefixes
        @inclusive_prefixes.keys
      end

      # :call-seq:
      #   canonicalize(node) -> String
      #   canonicalize(node, output) -> output
      #
      # Canonically serializes +node+ (a REXML::Document or Element subtree).
      # When +output+ (an object responding to +<<+) is given the canonical
      # bytes are written to it and it is returned; otherwise a UTF-8 encoded
      # String is returned.
      def canonicalize(node, output = nil)
        result = output || +''.dup
        case node
        when Document
          node.children.each do |child|
            write_document_level_node(child, result)
          end
        when Element
          write_element(node, result)
        else
          write_node(node, result, nil)
        end
        result.force_encoding(::Encoding::UTF_8) unless output
        result
      end

      alias write canonicalize

      private

      # Children of a document node have no rendered ancestor; comments and
      # processing instructions are followed by a newline when another
      # emitted document-level node comes after them.
      def write_document_level_node(node, output)
        case node
        when Element
          write_element(node, output)
          output << "\n" if emitted_document_node_after?(node)
        when Text
          # Text nodes that are children of the document node are outside
          # the document element and are never rendered.
        when Comment
          if @with_comments
            write_comment(node, output)
            output << "\n" if emitted_document_node_after?(node)
          end
        when Instruction
          write_instruction(node, output)
          output << "\n" if emitted_document_node_after?(node)
        end
      end

      def write_node(node, output, rendered_ancestors)
        case node
        when Element
          write_element(node, output, rendered_ancestors)
        when Text
          write_text(node, output)
        when Comment
          write_comment(node, output) if @with_comments
        when Instruction
          write_instruction(node, output)
        end
      end

      # Whether an emitted element, PI, or (when comments are kept)
      # comment follows +node+ among its document-level siblings.
      def emitted_document_node_after?(node)
        parent = node.parent
        return false unless parent
        siblings = parent.children
        index = siblings.index(node)
        ((index + 1)...siblings.length).each do |following|
          sibling = siblings[following]
          case sibling
          when Element
            return true
          when Instruction
            return true
          when Comment
            return true if @with_comments
          end
        end
        false
      end

      def write_text(node, output)
        output << escape_text_content(node.value)
      end

      def write_comment(node, output)
        output << '<!--'
        output << normalize_comment_whitespace(node.string.to_s)
        output << '-->'
      end

      def write_instruction(node, output)
        output << '<?'
        output << node.target
        content = node.content
        if content
          content = canonicalize_instruction_content(content)
          unless content.empty?
            output << ' '
            output << content
          end
        end
        output << '?>'
      end

      # State shared while descending one element tree. +rendered+ is a stack
      # of hashes mapping prefix => namespace URI for the declarations that
      # were actually rendered on each open output element.
      RenderedState = Struct.new(:rendered) do
        def find(prefix)
          rendered.reverse_each do |declarations|
            return declarations[prefix] if declarations.key?(prefix)
          end
          nil
        end

        def declared?(prefix, uri)
          find(prefix) == uri
        end

        def declared_anywhere?(prefix)
          rendered.reverse_each do |declarations|
            return true if declarations.key?(prefix)
          end
          false
        end
      end

      def write_element(element, output, rendered_state = nil)
        state = rendered_state || RenderedState.new([])
        stack = [[:enter, element]]
        until stack.empty?
          current = stack.pop
          case current
          when Array
            event, current = current
          else
            event = current.is_a?(Element) ? :enter : :node
          end
          case event
          when :enter
            open_element(current, output, state)
            stack.push([:exit, current])
            children = current.children
            unless children.empty?
              index = children.length
              while index > 0
                index -= 1
                stack.push([children[index].is_a?(Element) ? :enter : :node,
                            children[index]])
              end
            end
          when :exit
            close_element(current, output, state)
          when :node
            write_node(current, output, state)
          end
        end
      end

      def open_element(element, output, state)
        namespace_parts, own = render_namespace_declarations(element, state)
        state.rendered.push(own)
        output << '<' << element.expanded_name
        namespace_parts.each do |prefix, quoted|
          output << ' '
          if prefix.empty?
            output << 'xmlns=' << quoted
          else
            output << 'xmlns:' << prefix << '=' << quoted
          end
        end
        write_attributes(element, output)
        output << '>'
      end

      def close_element(element, output, state)
        output << '</' << element.expanded_name << '>'
        state.rendered.pop
      end

      # Returns the prefixes visibly utilized by +element+ itself: the prefix
      # of the element name and the prefixes of its non-xmlns attributes.
      def visibly_utilized_prefixes(element, set)
        prefix = element.prefix
        if prefix.nil? || prefix.empty?
          default_uri = in_scope_namespace(element, '')
          set[''] = true if default_uri && !default_uri.empty?
        elsif prefix != 'xml'
          set[prefix] = true
        end
        element.attributes.each_attribute do |attribute|
          next if attribute.namespace_declaration?
          attribute_prefix = attribute.prefix
          if attribute_prefix && !attribute_prefix.empty? &&
             attribute_prefix != 'xml'
            set[attribute_prefix] = true
          end
        end
      end

      # Renders the namespace axis subset for one element and returns a hash
      # of prefix => URI for everything rendered on it.
      def render_namespace_declarations(element, state)
        utilized = {}
        visibly_utilized_prefixes(element, utilized)

        # Prefixes from the InclusiveNamespaces PrefixList that are in scope
        # here are carried inclusively. "#default" is stored as "".
        @inclusive_prefixes.each_key do |prefix|
          uri = in_scope_namespace(element, prefix)
          next if uri.nil?
          # The default namespace is only carried inclusively where it is
          # actually bound; an empty binding is handled by the clearing
          # rule below.
          next if prefix.empty? && uri.empty?
          utilized[prefix] = true
        end

        # An unprefixed element in no namespace reached through a rendered
        # non-empty default namespace needs xmlns="" to clear it.
        unless utilized.key?('')
          nearest = nearest_rendered_default(state)
          if nearest && !nearest.empty?
            default_uri = in_scope_namespace(element, '') || ''
            utilized[''] = true if default_uri.empty?
          end
        end

        declarations = {}
        namespace_parts = []
        utilized.keys.sort.each do |prefix|
          uri = in_scope_namespace(element, prefix)
          # A utilized prefix with no binding would make the input document
          # ill-formed; there is nothing to render in that case.
          next if uri.nil?

          if prefix.empty?
            nearest = nearest_rendered_default(state)
            next if nearest == uri
            declarations[''] = uri
            namespace_parts.unshift(['', quoted_attribute_value(uri)])
          else
            inclusive = @inclusive_prefixes.key?(prefix)
            already = if inclusive
                        state.declared_anywhere?(prefix) &&
                          state.find(prefix) == uri
                      else
                        state.declared?(prefix, uri)
                      end
            next if already
            declarations[prefix] = uri
            namespace_parts << [prefix, quoted_attribute_value(uri)]
          end
        end
        [namespace_parts, declarations]
      end

      # URI currently bound to +prefix+ (empty prefix for the default
      # namespace) in the scope of +element+, or nil if unbound. The default
      # namespace that has never been declared is reported as nil rather than
      # the empty string.
      def in_scope_namespace(element, prefix)
        current = element
        name = prefix.empty? ? 'xmlns' : "xmlns:#{prefix}"
        while current
          attribute = current.attributes.get_attribute(name)
          unless attribute.nil?
            uri = attribute.value
            return prefix.empty? && uri.nil? ? '' : uri
          end
          current = current.parent
          # The default namespace does not cross the document boundary.
          current = nil if current.is_a?(Document)
        end
        if prefix == 'xml'
          return 'http://www.w3.org/XML/1998/namespace'
        end
        nil
      end

      def nearest_rendered_default(state)
        state.rendered.reverse_each do |declarations|
          return declarations[''] if declarations.key?('')
        end
        nil
      end

      def write_attributes(element, output)
        sorted = []
        element.attributes.each_attribute do |attribute|
          next if attribute.namespace_declaration?
          sorted << attribute
        end
        sorted.sort_by! do |attribute|
          namespace_uri = attribute.namespace(attribute.prefix) || ''
          local_name = attribute.name
          [namespace_uri, local_name, attribute.expanded_name]
        end
        sorted.each do |attribute|
          output << ' '
          output << attribute.expanded_name
          output << '='
          output << quoted_attribute_value(attribute.value)
        end
      end

      def quoted_attribute_value(value)
        '"' + escape_attribute_value(value) + '"'
      end

      def normalize_comment_whitespace(value)
        value
          .gsub("\t", ' ')
          .gsub("\n", ' ')
          .gsub("\r", ' ')
      end

      def canonicalize_instruction_content(value)
        value
          .gsub("\t", ' ')
          .gsub("\n", ' ')
          .gsub("\r", ' ')
          .lstrip
      end

      def escape_text_content(value)
        value
          .gsub('&', '&amp;')
          .gsub('<', '&lt;')
          .gsub('>', '&gt;')
          .gsub("\r", '&#xD;')
      end

      def escape_attribute_value(value)
        value
          .gsub('&', '&amp;')
          .gsub('<', '&lt;')
          .gsub('"', '&quot;')
          .gsub("\t", '&#x9;')
          .gsub("\n", '&#xA;')
          .gsub("\r", '&#xD;')
      end
    end
  end
end
