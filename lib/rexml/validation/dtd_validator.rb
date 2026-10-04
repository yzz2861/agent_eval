# frozen_string_literal: true

require_relative "../document"
require_relative "validationexception"

module REXML
  module Validation
    # Validates the children of elements against the content models declared
    # by DTD <!ELEMENT ...> declarations.
    #
    # Supported content models:
    #
    # * EMPTY
    # * ANY
    # * mixed content: (#PCDATA) and (#PCDATA|a|b)*
    # * element content: sequences (a,b), choices (a|b), nested groups and
    #   the ?, * and + occurrence indicators
    #
    # The validator only uses declarations found in the document's internal
    # DTD subset or in a DTD string supplied by the caller.  External DTDs
    # referenced through SYSTEM or PUBLIC identifiers are never fetched.
    #
    # Comments and processing instructions are ignored.  Character data is
    # checked against the content model: whitespace-only text is always
    # allowed, any other text only where the model permits it.
    #
    #   validator = REXML::Validation::DTDValidator.new(document)
    #   validator.validate(document) # => true, or raises ValidationException
    #
    #   validator = REXML::Validation::DTDValidator.new("<!ELEMENT a (b+)>")
    #   validator.validate(element)
    class DTDValidator
      ELEMENT_DECLARATION = /<!ELEMENT\s+([^\s>]+)\s+([^>]*?)\s*>/m

      def initialize(dtd_source)
        @declarations = {}
        @doctype_name = nil
        case dtd_source
        when REXML::Document
          doctype = dtd_source.doctype
          unless doctype
            raise ArgumentError,
                  "the document has no DTD; " \
                  "pass a DTD string or a REXML::DocType instead"
          end
          load_doctype(doctype)
        when REXML::DocType
          load_doctype(dtd_source)
        when String
          scan_declarations(dtd_source)
        else
          raise ArgumentError,
                "expected a REXML::Document, REXML::DocType or DTD String, " \
                "got #{dtd_source.class}"
        end
      end

      # Validates a REXML::Document or REXML::Element against the content
      # models.  Returns true when valid, raises
      # REXML::Validation::ValidationException otherwise.
      def validate(node)
        case node
        when REXML::Document
          root = node.root
          unless root
            raise ValidationException, "document has no root element"
          end
          if @doctype_name && root.expanded_name != @doctype_name
            raise ValidationException,
                  "/#{root.expanded_name}: root element " \
                  "<#{root.expanded_name}> does not match " \
                  "the DOCTYPE name <#{@doctype_name}>"
          end
          validate_element(root, "/#{root.expanded_name}")
        when REXML::Element
          validate_element(node, "/#{node.expanded_name}")
        else
          raise ArgumentError,
                "expected a REXML::Document or REXML::Element, " \
                "got #{node.class}"
        end
        true
      end

      private

      def load_doctype(doctype)
        @doctype_name = doctype.name
        doctype.children.each do |child|
          next unless child.is_a?(REXML::ElementDecl)
          add_declaration(child.to_s)
        end
      end

      def scan_declarations(dtd)
        dtd.scan(ELEMENT_DECLARATION) do |name, content_spec|
          @declarations[name] ||= parse_declaration(name, content_spec)
        end
      end

      def add_declaration(declaration)
        match = ELEMENT_DECLARATION.match(declaration)
        return unless match
        @declarations[match[1]] ||= parse_declaration(match[1], match[2])
      end

      def parse_declaration(name, content_spec)
        spec = content_spec.strip
        case spec
        when "EMPTY"
          ElementDeclaration.new(name, :empty)
        when "ANY"
          ElementDeclaration.new(name, :any)
        else
          ContentSpecParser.new(name, spec).parse
        end
      end

      def validate_element(element, path)
        declaration = @declarations[element.expanded_name]
        unless declaration
          raise ValidationException,
                "#{path}: element <#{element.expanded_name}> " \
                "is not declared in the DTD"
        end
        check_content(declaration, element, path)
        validate_children(element, path)
      end

      def validate_children(element, path)
        totals = Hash.new(0)
        element.children.each do |child|
          totals[child.expanded_name] += 1 if child.is_a?(REXML::Element)
        end
        seen = Hash.new(0)
        element.children.each do |child|
          next unless child.is_a?(REXML::Element)
          seen[child.expanded_name] += 1
          name = child.expanded_name
          name = "#{name}[#{seen[name]}]" if totals[name] > 1
          validate_element(child, "#{path}/#{name}")
        end
      end

      def check_content(declaration, element, path)
        case declaration.kind
        when :any
          # No constraints on the children.
        when :empty
          check_empty_content(declaration, element, path)
        when :mixed
          check_mixed_content(declaration, element, path)
        when :children
          check_element_content(declaration, element, path)
        end
      end

      def check_empty_content(declaration, element, path)
        element.children.each do |child|
          case child
          when REXML::Element
            raise ValidationException,
                  "#{path}: unexpected element <#{child.expanded_name}>; " \
                  "<#{declaration.name}> is declared EMPTY"
          when REXML::Text
            next if whitespace?(child)
            raise ValidationException,
                  "#{path}: unexpected text #{text_snippet(child)}; " \
                  "<#{declaration.name}> is declared EMPTY"
          end
        end
      end

      def check_mixed_content(declaration, element, path)
        element.children.each do |child|
          next unless child.is_a?(REXML::Element)
          next if declaration.names.include?(child.expanded_name)
          raise ValidationException,
                "#{path}: unexpected element <#{child.expanded_name}>; " \
                "expected #{mixed_expectation(declaration)}"
        end
      end

      def check_element_content(declaration, element, path)
        model = declaration.model
        element.children.each do |child|
          case child
          when REXML::Element
            derived = model.derive(child.expanded_name)
            if derived.impossible?
              raise ValidationException,
                    "#{path}: unexpected element <#{child.expanded_name}>; " \
                    "expected #{expectation(model)}"
            end
            model = derived
          when REXML::Text
            next if whitespace?(child)
            raise ValidationException,
                  "#{path}: unexpected text #{text_snippet(child)}; " \
                  "expected #{expectation(model)}"
          end
        end
        unless model.nullable?
          raise ValidationException,
                "#{path}: unexpected end of <#{declaration.name}>; " \
                "expected #{expectation(model)}"
        end
      end

      def expectation(model)
        expected = model.first.map {|name| "<#{name}>" }
        expected << "end of element" if model.nullable?
        return "nothing" if expected.empty?
        expected.join(" or ")
      end

      def mixed_expectation(declaration)
        return "no child elements" if declaration.names.empty?
        declaration.names.map {|name| "<#{name}>" }.join(" or ")
      end

      def whitespace?(text)
        text.value.strip.empty?
      end

      def text_snippet(text)
        snippet = text.value.strip
        snippet = snippet[0, 20] + "..." if snippet.length > 20
        snippet.inspect
      end

      # The parsed form of a single <!ELEMENT> declaration.
      class ElementDeclaration
        attr_reader :name, :kind, :names, :model

        def initialize(name, kind, names=nil, model=nil)
          @name = name
          @kind = kind
          @names = names
          @model = model
        end
      end

      # Regular-expression-like nodes over element names.  Sequences of
      # child element names are matched with Brzozowski derivatives: each
      # consumed name rewrites the model into the model that remains, so
      # the document itself is never converted into a string.
      module ContentModel
        class Never
          def nullable?
            false
          end

          def first
            []
          end

          def derive(name)
            self
          end

          def impossible?
            true
          end
        end
        NEVER = Never.new

        class Epsilon
          def nullable?
            true
          end

          def first
            []
          end

          def derive(name)
            NEVER
          end

          def impossible?
            false
          end
        end
        EPSILON = Epsilon.new

        class Literal
          def initialize(name)
            @name = name
          end

          def nullable?
            false
          end

          def first
            [@name]
          end

          def derive(name)
            name == @name ? EPSILON : NEVER
          end

          def impossible?
            false
          end
        end

        class Sequence
          def initialize(left, right)
            @left = left
            @right = right
          end

          def nullable?
            @left.nullable? && @right.nullable?
          end

          def first
            @left.nullable? ? @left.first | @right.first : @left.first
          end

          def derive(name)
            derived = Sequence.new(@left.derive(name), @right)
            if @left.nullable?
              Choice.new(derived, @right.derive(name))
            else
              derived
            end
          end

          def impossible?
            @left.impossible? || @right.impossible?
          end
        end

        class Choice
          def initialize(left, right)
            @left = left
            @right = right
          end

          def nullable?
            @left.nullable? || @right.nullable?
          end

          def first
            @left.first | @right.first
          end

          def derive(name)
            Choice.new(@left.derive(name), @right.derive(name))
          end

          def impossible?
            @left.impossible? && @right.impossible?
          end
        end

        class Star
          def initialize(child)
            @child = child
          end

          def nullable?
            true
          end

          def first
            @child.first
          end

          def derive(name)
            Sequence.new(@child.derive(name), self)
          end

          def impossible?
            false
          end
        end
      end

      # Recursive descent parser for DTD content specifications such as
      # "(a,(b|c)*,d?)" or "(#PCDATA|em)*".
      class ContentSpecParser
        def initialize(element_name, spec)
          @element_name = element_name
          @spec = spec
          @tokens = tokenize(spec)
          @index = 0
        end

        def parse
          expect("(")
          if peek == :pcdata
            parse_mixed
          else
            model = parse_content_particles
            expect(")")
            model = quantify(model)
            finish
            ElementDeclaration.new(@element_name, :children, nil, model)
          end
        end

        private

        def parse_mixed
          take # :pcdata
          names = []
          if peek == ")"
            take
            finish
            return ElementDeclaration.new(@element_name, :mixed, names)
          end
          loop do
            expect("|")
            token = take
            unless token.is_a?(Array) && token[0] == :name
              error("expected an element name, got #{token.inspect}")
            end
            names << token[1]
            break if peek == ")"
          end
          expect(")")
          expect("*")
          finish
          ElementDeclaration.new(@element_name, :mixed, names)
        end

        # Parses cp (S? separator S? cp)* up to (but not consuming) ")".
        def parse_content_particles
          particles = [parse_cp]
          separator = nil
          loop do
            token = peek
            break unless token == "," || token == "|"
            if separator && separator != token
              error("cannot mix ',' and '|' in the same group")
            end
            separator = token
            take
            particles << parse_cp
          end
          if separator == "|"
            particles.reduce {|left, right| ContentModel::Choice.new(left, right) }
          else
            particles.reduce {|left, right| ContentModel::Sequence.new(left, right) }
          end
        end

        def parse_cp
          token = take
          if token == "("
            model = parse_content_particles
            expect(")")
          elsif token.is_a?(Array) && token[0] == :name
            model = ContentModel::Literal.new(token[1])
          else
            error("expected an element name or '(', got #{token.inspect}")
          end
          quantify(model)
        end

        def quantify(model)
          case peek
          when "?"
            take
            ContentModel::Choice.new(model, ContentModel::EPSILON)
          when "*"
            take
            ContentModel::Star.new(model)
          when "+"
            take
            ContentModel::Sequence.new(model, ContentModel::Star.new(model))
          else
            model
          end
        end

        def tokenize(spec)
          tokens = []
          rest = spec
          until rest.empty?
            case rest
            when /\A\s+/
              rest = $~.post_match
            when /\A#PCDATA/
              tokens << :pcdata
              rest = $~.post_match
            when /\A[()|,?*+]/
              tokens << $~[0]
              rest = $~.post_match
            when /\A[^\s()|,?*+]+/
              tokens << [:name, $~[0]]
              rest = $~.post_match
            else
              error("cannot parse content specification")
            end
          end
          tokens
        end

        def peek
          @tokens[@index]
        end

        def take
          token = @tokens[@index]
          @index += 1
          token
        end

        def expect(token)
          actual = take
          unless actual == token
            error("expected #{token.inspect}, got #{actual.inspect}")
          end
        end

        def finish
          if @index < @tokens.size
            error("unexpected #{@tokens[@index].inspect} after content model")
          end
        end

        def error(message)
          raise ValidationException,
                "invalid content model for element <#{@element_name}>: " \
                "#{message} in #{@spec.inspect}"
        end
      end
    end
  end
end
