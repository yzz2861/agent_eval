# frozen_string_literal: false

require_relative "validationexception"
require_relative "dtd/content_model"

module REXML
  module Validation
    # Validates a parsed document or element subtree against DTD
    # element declarations.
    #
    # The supported content specification forms are:
    # - +EMPTY+
    # - +ANY+
    # - mixed content: +(#PCDATA)+ and +(#PCDATA | name | ...)*+
    # - element content with element names, sequences, choices, groups
    #   and the +?+, +*+ and +++ occurrence indicators
    #
    # Comments and processing instructions are ignored while checking
    # element children.  Whitespace-only text is ignored; any other
    # character data is judged against the element's content model.
    #
    # Only declarations found in the document's internal subset and
    # declarations explicitly supplied by the caller are used.
    # External resources referenced by a +DOCTYPE+ are never fetched.
    #
    # == Example
    #
    #   require "rexml/document"
    #   require "rexml/validation/dtd"
    #
    #   xml = <<-XML
    #   <!DOCTYPE memo [
    #     <!ELEMENT memo (title, body)>
    #     <!ELEMENT title (#PCDATA)>
    #     <!ELEMENT body (#PCDATA)>
    #   ]>
    #   <memo><title/><body>hello</body></memo>
    #   XML
    #   document = REXML::Document.new(xml)
    #   REXML::Validation::DTD.validate(document)
    #   # raises REXML::Validation::ValidationException
    class DTD
      ELEMENT_DECLARATION_PATTERN =
        /<!ELEMENT\s+([^\s>]+)\s+([^>]*?)>/m

      # Validates +document_or_element+ against the DTD declarations
      # already attached to it (or given in +dtd+).
      def self.validate(document_or_element, dtd = nil)
        new(document_or_element, dtd).validate
      end

      # Creates a validator.
      #
      # +document_or_element+ is either a REXML::Document or a
      # REXML::Element.  When it is a Document, its internal DTD subset
      # is used automatically; an external DTD is never fetched.
      #
      # +dtd+ optionally provides additional element declarations.
      # It may be a REXML::DocType or a String containing
      # +<!ELEMENT>+ declarations (for example, the content of an
      # external DTD that the caller has loaded by other means).
      # Declarations from the document's internal subset take
      # precedence over declarations supplied here.
      def initialize(document_or_element, dtd = nil)
        @declarations = {}
        if document_or_element.is_a?(REXML::Document)
          @document = document_or_element
          @element = @document.root
          load_declarations(@document.doctype)
        else
          @document = nil
          @element = document_or_element
        end
        load_declarations(dtd)
        @models = {}
        @declarations.each do |name, specification|
          @models[name] = ContentModel.parse(specification)
        end
      end

      # Runs the validation and returns the validated object on
      # success.  Raises ValidationException on the first content
      # model violation.
      def validate
        if @document and (doctype = @document.doctype) and
           doctype.name and @element and
           @element.expanded_name != doctype.name
          raise ValidationException,
                "DTD root element must be <#{doctype.name}>, " \
                "but got <#{@element.expanded_name}> at " \
                "/#{@element.expanded_name}"
        end
        validate_element(@element, "/", {}) if @element
        @document || @element
      end

      private

      def load_declarations(source)
        case source
        when nil
          return
        when REXML::DocType
          source.children.each do |child|
            register_declaration_text(child.to_s) if
              child.is_a?(REXML::ElementDecl)
          end
        when String
          register_declaration_text(source)
        else
          raise ArgumentError,
                "unsupported DTD source: #{source.class}"
        end
      end

      def register_declaration_text(text)
        source = text.dup
        source.gsub!(/<!--.*?-->/m, "")
        source.gsub!(/<\?.*?\?>/m, "")
        source.scan(ELEMENT_DECLARATION_PATTERN) do |name, specification|
          @declarations[name] ||= specification.strip
        end
      end

      def validate_element(element, parent_path, siblings_count)
        path = element_path(element, parent_path, siblings_count)
        model = @models[element.expanded_name]
        if model.nil?
          if @models.any?
            raise ValidationException,
                  "element <#{element.expanded_name}> is not declared " \
                  "in the DTD at #{path}"
          end
        end
        validate_children(element, path, model)
      end

      def validate_children(element, path, model)
        counts = Hash.new(0)
        states = model.initial_states if
          model and model.kind == ContentModel::ELEMENTS

        element.children.each do |child|
          next if child.is_a?(REXML::Comment) or
                  child.is_a?(REXML::Instruction)

          if child.is_a?(REXML::Text)
            next if child.to_s.strip.empty?
            check_text(element, path, child, model, states)
            next
          end
          next unless child.is_a?(REXML::Element)

          name = child.expanded_name
          counts[name] += 1
          if @models.any? and not @models.key?(name)
            raise ValidationException,
                  "element <#{name}> is not declared in the DTD at " \
                  "#{element_path(child, path, counts)}"
          end
          states = check_element_child(element, path, child, name,
                                       model, states, counts) if model
          validate_element(child, path, counts)
        end

        if model and model.kind == ContentModel::ELEMENTS and
           !model.accepting?(states || [])
          expected = model.expected_labels(states || [])
          message =
            "content of <#{element.expanded_name}> at #{path} ended " \
            "before its content model was satisfied"
          if expected.any?
            message += "; acceptable successors: " \
                       "#{successor_list(expected)}"
          end
          raise ValidationException, message
        end
      end

      def check_text(element, path, node, model, states)
        return if model.nil? or model.allows_text?
        if model.empty?
          raise ValidationException,
                "element <#{element.expanded_name}> is declared EMPTY " \
                "but contains non-whitespace text at #{path}: " \
                "#{describe_text(node)}; acceptable successors: " \
                "(end of content)"
        end
        expected = model.expected_labels(states || model.initial_states)
        raise ValidationException,
              "element <#{element.expanded_name}> has an element-only " \
              "content model but contains non-whitespace text at " \
              "#{path}: #{describe_text(node)}; acceptable successors: " \
              "#{successor_list(expected)}"
      end

      def check_element_child(element, path, child, name, model,
                              states, counts)
        case model.kind
        when ContentModel::EMPTY
          raise_unexpected(element, path, child, counts, nil, true)
        when ContentModel::ELEMENTS
          next_states = model.consume(states, name)
          if next_states.nil?
            expected = model.expected_labels(states)
            complete = model.accepting?(states) and expected.empty?
            raise_unexpected(element, path, child, counts,
                             expected, complete)
          end
          states = next_states
        when ContentModel::MIXED
          unless model.allowed_names.include?(name)
            raise ValidationException,
                  "element <#{name}> is not allowed in the mixed " \
                  "content model of <#{element.expanded_name}> at " \
                  "#{element_path(child, path, counts)}; " \
                  "acceptable elements: " \
                  "#{successor_list(model.allowed_names)}"
          end
          states
        end
      end

      def raise_unexpected(element, path, child, siblings_count,
                           expected, complete)
        child_path = element_path(child, path, siblings_count)
        message =
          "unexpected element <#{child.expanded_name}> in " \
          "<#{element.expanded_name}> at #{child_path}"
        if complete
          message += "; acceptable successors: (end of content)"
        elsif expected.empty?
          message += "; no further child elements are allowed"
        else
          message += "; acceptable successors: " \
                     "#{successor_list(expected)}"
        end
        raise ValidationException, message
      end

      def successor_list(names)
        return "(none)" if names.empty?
        names.uniq.collect { |name| "<#{name}>" }.join(", ")
      end

      def describe_text(node)
        value = node.to_s
        value = value[0, 32] + "..." if value.length > 32
        kind = node.is_a?(REXML::CData) ? "CDATA" : "text"
        "#{kind} #{value.inspect}"
      end

      def element_path(element, parent_path, siblings_count)
        name = element.expanded_name
        separator = parent_path.end_with?("/") ? "" : "/"
        path = +"#{parent_path}#{separator}#{name}"
        index = siblings_count[name]
        if index and index > 1
          path << "[#{index}]"
        end
        path
      end
    end
  end
end
