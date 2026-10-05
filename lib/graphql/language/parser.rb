# frozen_string_literal: true

require "strscan"
require "graphql/language/nodes"
require "graphql/tracing/null_trace"

module GraphQL
  module Language
    class Parser
      include GraphQL::Language::Nodes
      include EmptyObjects

      class << self
        attr_accessor :cache

        def parse(graphql_str, filename: nil, trace: Tracing::NullTrace, max_tokens: nil)
          self.new(graphql_str, filename: filename, trace: trace, max_tokens: max_tokens).parse
        end

        # Fault-tolerant parse: unlike {.parse}, syntax errors don't abort the
        # whole document. The returned {ParseResult} contains a partial AST
        # (with {Nodes::SyntaxError} and {Nodes::MissingToken} nodes marking the
        # broken regions) and one diagnostic per syntax problem.
        #
        # The strict parser is deliberately left unchanged: anything that would
        # come out of this entry point must never flow into normal execution.
        def parse_with_recovery(graphql_str, filename: nil, trace: Tracing::NullTrace, max_tokens: nil)
          begin
            parser_instance = self.new(graphql_str, filename: filename, trace: trace, max_tokens: max_tokens, tolerant: true)
          rescue GraphQL::ParseError => err
            return ParseResult.new(document: nil, errors: [err])
          end
          parser_instance.parse_with_recovery
        end

        def parse_file(filename, trace: Tracing::NullTrace)
          if cache
            cache.fetch(filename) do
              parse(File.read(filename), filename: filename, trace: trace)
            end
          else
            parse(File.read(filename), filename: filename, trace: trace)
          end
        end
      end

      def initialize(graphql_str, filename: nil, trace: Tracing::NullTrace, max_tokens: nil, tolerant: false)
        if graphql_str.nil?
          raise GraphQL::ParseError.new("No query string was present", nil, nil, nil)
        end
        @lexer = Lexer.new(graphql_str, filename: filename, max_tokens: max_tokens, tolerant: tolerant)
        @graphql_str = graphql_str
        @filename = filename
        @trace = trace
        @dedup_identifiers = false
        @lines_at = nil
        @tolerant = tolerant
        @diagnostics = [] if tolerant
      end

      def parse
        @document ||= begin
          @trace.parse(query_string: @graphql_str) do
            document
          end
        rescue SystemStackError
          raise GraphQL::ParseError.new("This query is too large to execute.", nil, nil, @query_str, filename: @filename)
        end
      end

      def tokens_count
        parse
        @lexer.tokens_count
      end

      # Result of a fault-tolerant parse. A document built with recovery is
      # only useful together with its diagnostics -- never execute it.
      class ParseResult
        # @return [Nodes::Document, nil] Partial document, or nil when parsing could not start
        attr_reader :document
        # @return [Array<GraphQL::ParseError>] One entry per syntax problem encountered
        attr_reader :errors

        def initialize(document:, errors:)
          @document = document
          @errors = errors
        end

        # @return [Boolean] Was the source syntactically valid?
        def ok?
          @errors.empty?
        end

        alias_method :valid?, :ok?
      end

      def parse_with_recovery
        ParseResult.new(
          document: parse,
          errors: @diagnostics
        )
      rescue GraphQL::ParseError => err
        record_diagnostic(err)
        ParseResult.new(document: nil, errors: @diagnostics)
      end

      def line_at(pos)
        line = lines_at.bsearch_index { |l| l >= pos }
        if line.nil?
          @lines_at.size + 1
        else
          line + 1
        end
      end

      def column_at(pos)
        next_line_idx = lines_at.bsearch_index { |l| l >= pos } || 0
        if next_line_idx > 0
          line_pos = @lines_at[next_line_idx - 1]
          pos - line_pos
        else
          pos + 1
        end
      end

      private

      # @return [Array<Integer>] Positions of each line break in the original string
      def lines_at
        @lines_at ||= begin
          la = []
          idx = 0
          while idx
            idx = @graphql_str.index("\n", idx)
            if idx
              la << idx
              idx += 1
            end
          end
          la
        end
      end

      attr_reader :token_name

      def advance_token
        @token_name = @lexer.advance
      end

      def pos
        @lexer.pos
      end

      def document
        any_tokens = advance_token
        if !@tolerant
          defns = []
          if any_tokens
            defns << definition
          else
            # Only ignored characters is not a valid document
            raise GraphQL::ParseError.new("Unexpected end of document", nil, nil, @graphql_str)
          end
          while !@lexer.finished?
            defns << definition
          end
          return Document.new(pos: 0, definitions: defns, filename: @filename, source: self)
        end

        defns = []
        if !any_tokens
          record_diagnostic(GraphQL::ParseError.new("Unexpected end of document", nil, nil, @graphql_str, filename: @filename))
        end
        while !@lexer.finished?
          if CLOSERS.include?(@token_name)
            # A stray closer with no open container: report it explicitly
            # (its span is just the single punctuation token) and consume it.
            error_start = current_pos
            err = parse_error_at_current("Unexpected #{@token_name} (#{debug_token_value.inspect}) at [#{@lexer.line_number}, #{@lexer.column_number}]")
            record_diagnostic(err)
            advance_token
            defns << syntax_error_node(error_start, err.message, end_pos: current_pos)
            next
          end
          error_start = current_pos
          begin
            defns << definition
          rescue GraphQL::ParseError => err
            record_diagnostic(err)
            status = resync(stop: [], bail: [], restart: DEFINITION_START_TOKENS, error_start: error_start)
            case status
            when :restart, :restart_with_junk
              defns << syntax_error_node(error_start, err.message) if status == :restart_with_junk
              next
            when :junk
              defns << syntax_error_node(error_start, err.message)
            when :unmatched
              defns << syntax_error_node(error_start, err.message)
              @lexer.finished? ? break : next
            end
          end
        end
        Document.new(pos: 0, definitions: defns, filename: @filename, source: self)
      end

      def definition
        case token_name
        when :FRAGMENT
          loc = pos
          expect_token :FRAGMENT
          f_name = if !at?(:ON)
            parse_name
          end
          expect_token :ON
          f_type = parse_type_name
          directives = parse_directives
          selections = selection_set
          Nodes::FragmentDefinition.new(
            pos: loc,
            name: f_name,
            type: f_type,
            directives: directives,
            selections: selections,
            filename: @filename,
            source: self
          )
        when :QUERY, :MUTATION, :SUBSCRIPTION, :LCURLY
          op_loc = pos
          op_type = case token_name
          when :LCURLY
            "query"
          else
            parse_operation_type
          end

          op_name = case token_name
          when :LPAREN, :LCURLY, :DIR_SIGN
            nil
          else
            parse_name
          end

          variable_definitions = if at?(:LPAREN)
            advance_token
            if !@tolerant
              defs = []
              while !at?(:RPAREN)
                defs << parse_variable_definition
              end
              expect_token(:RPAREN)
              defs
            else
              defs, status = parse_container_elements(
                closer: :RPAREN,
                bail: [:LCURLY, :RCURLY],
                restart: [:VAR_SIGN] + NAME_KEYWORD_TOKENS,
              ) { parse_variable_definition }
              expect_closer(:RPAREN) if status == :ok
              defs
            end
          else
            EmptyObjects::EMPTY_ARRAY
          end

          directives = parse_directives

          OperationDefinition.new(
            pos: op_loc,
            operation_type: op_type,
            name: op_name,
            variables: variable_definitions,
            directives: directives,
            selections: selection_set,
            filename: @filename,
            source: self
          )
        when :EXTEND
          loc = pos
          advance_token
          case token_name
          when :SCALAR
            advance_token
            name = parse_name
            directives = parse_directives
            ScalarTypeExtension.new(pos: loc, name: name, directives: directives, filename: @filename, source: self)
          when :TYPE
            advance_token
            name = parse_name
            implements_interfaces = parse_implements
            directives = parse_directives
            field_defns = at?(:LCURLY) ? parse_field_definitions : EMPTY_ARRAY

            ObjectTypeExtension.new(pos: loc, name: name, interfaces: implements_interfaces, directives: directives, fields: field_defns, filename: @filename, source: self)
          when :INTERFACE
            advance_token
            name = parse_name
            directives = parse_directives
            interfaces = parse_implements
            fields_definition = at?(:LCURLY) ? parse_field_definitions : EMPTY_ARRAY
            InterfaceTypeExtension.new(pos: loc, name: name, directives: directives, fields: fields_definition, interfaces: interfaces, filename: @filename, source: self)
          when :UNION
            advance_token
            name = parse_name
            directives = parse_directives
            union_member_types = parse_union_members
            UnionTypeExtension.new(pos: loc, name: name, directives: directives, types: union_member_types, filename: @filename, source: self)
          when :ENUM
            advance_token
            name = parse_name
            directives = parse_directives
            enum_values_definition = parse_enum_value_definitions
            Nodes::EnumTypeExtension.new(pos: loc, name: name, directives: directives, values: enum_values_definition, filename: @filename, source: self)
          when :INPUT
            advance_token
            name = parse_name
            directives = parse_directives
            input_fields_definition = parse_input_object_field_definitions
            InputObjectTypeExtension.new(pos: loc, name: name, directives: directives, fields: input_fields_definition, filename: @filename, source: self)
          when :SCHEMA
            advance_token
            directives = parse_directives
            query = mutation = subscription = nil
            if at?(:LCURLY)
              advance_token
              while !at?(:RCURLY)
                if at?(:QUERY)
                  advance_token
                  expect_token(:COLON)
                  query = parse_name
                elsif at?(:MUTATION)
                  advance_token
                  expect_token(:COLON)
                  mutation = parse_name
                elsif at?(:SUBSCRIPTION)
                  advance_token
                  expect_token(:COLON)
                  subscription = parse_name
                else
                  expect_one_of([:QUERY, :MUTATION, :SUBSCRIPTION])
                end
              end
              expect_token :RCURLY
            end
            SchemaExtension.new(
              subscription: subscription,
              mutation: mutation,
              query: query,
              directives: directives,
              pos: loc,
              filename: @filename,
              source: self,
            )
          else
            expect_one_of([:SCHEMA, :SCALAR, :TYPE, :ENUM, :INPUT, :UNION, :INTERFACE])
          end
        else
          loc = pos
          desc = at?(:STRING) ? string_value : nil
          defn_loc = pos
          case token_name
          when :SCHEMA
            advance_token
            directives = parse_directives
            query = mutation = subscription = nil
            expect_token :LCURLY
            while !at?(:RCURLY)
              if at?(:QUERY)
                advance_token
                expect_token(:COLON)
                query = parse_name
              elsif at?(:MUTATION)
                advance_token
                expect_token(:COLON)
                mutation = parse_name
              elsif at?(:SUBSCRIPTION)
                advance_token
                expect_token(:COLON)
                subscription = parse_name
              else
                expect_one_of([:QUERY, :MUTATION, :SUBSCRIPTION])
              end
            end
            expect_token :RCURLY
            SchemaDefinition.new(pos: loc, definition_pos: defn_loc, query: query, mutation: mutation, subscription: subscription, directives: directives, filename: @filename, source: self)
          when :DIRECTIVE
            advance_token
            expect_token :DIR_SIGN
            name = parse_name
            arguments_definition = parse_argument_definitions
            repeatable = if at?(:REPEATABLE)
              advance_token
              true
            else
              false
            end
            expect_token :ON
            directive_locations = [DirectiveLocation.new(pos: pos, name: parse_name, filename: @filename, source: self)]
            while at?(:PIPE)
              advance_token
              directive_locations << DirectiveLocation.new(pos: pos, name: parse_name, filename: @filename, source: self)
            end
            DirectiveDefinition.new(pos: loc, definition_pos: defn_loc, description: desc, name: name, arguments: arguments_definition, locations: directive_locations, repeatable: repeatable, filename: @filename, source: self)
          when :TYPE
            advance_token
            name = parse_name
            implements_interfaces = parse_implements
            directives = parse_directives
            field_defns = at?(:LCURLY) ? parse_field_definitions : EMPTY_ARRAY

            ObjectTypeDefinition.new(pos: loc, definition_pos: defn_loc, description: desc, name: name, interfaces: implements_interfaces, directives: directives, fields: field_defns, filename: @filename, source: self)
          when :INTERFACE
            advance_token
            name = parse_name
            interfaces = parse_implements
            directives = parse_directives
            fields_definition = parse_field_definitions
            InterfaceTypeDefinition.new(pos: loc, definition_pos: defn_loc, description: desc, name: name, directives: directives, fields: fields_definition, interfaces: interfaces, filename: @filename, source: self)
          when :UNION
            advance_token
            name = parse_name
            directives = parse_directives
            union_member_types = parse_union_members
            UnionTypeDefinition.new(pos: loc, definition_pos: defn_loc, description: desc, name: name, directives: directives, types: union_member_types, filename: @filename, source: self)
          when :SCALAR
            advance_token
            name = parse_name
            directives = parse_directives
            ScalarTypeDefinition.new(pos: loc, definition_pos: defn_loc, description: desc, name: name, directives: directives, filename: @filename, source: self)
          when :ENUM
            advance_token
            name = parse_name
            directives = parse_directives
            enum_values_definition = parse_enum_value_definitions
            Nodes::EnumTypeDefinition.new(pos: loc, definition_pos: defn_loc, description: desc, name: name, directives: directives, values: enum_values_definition, filename: @filename, source: self)
          when :INPUT
            advance_token
            name = parse_name
            directives = parse_directives
            input_fields_definition = parse_input_object_field_definitions
            InputObjectTypeDefinition.new(pos: loc, definition_pos: defn_loc, description: desc, name: name, directives: directives, fields: input_fields_definition, filename: @filename, source: self)
          else
            expect_one_of([:SCHEMA, :SCALAR, :TYPE, :ENUM, :INPUT, :UNION, :INTERFACE])
          end
        end
      end

      def parse_input_object_field_definitions
        if at?(:LCURLY)
          advance_token
          if !@tolerant
            list = []
            while !at?(:RCURLY)
              list << parse_input_value_definition
            end
            expect_token(:RCURLY)
            return list
          end
          list, = parse_container_elements(
            closer: :RCURLY,
            bail: [],
            restart: DEFINITION_FIELD_START_TOKENS,
          ) { parse_input_value_definition }
          expect_closer(:RCURLY) if at?(:RCURLY)
          list
        else
          EMPTY_ARRAY
        end
      end

      def parse_enum_value_definitions
        if at?(:LCURLY)
          expect_token :LCURLY
          list = []
          while !at?(:RCURLY)
            v_loc = pos
            description = if at?(:STRING); string_value; end
            defn_loc = pos
            # Any identifier, but not true, false, or null
            enum_value = if at?(:TRUE) || at?(:FALSE) || at?(:NULL)
              expect_token(:IDENTIFIER)
            else
              parse_name
            end
            v_directives = parse_directives
            list << EnumValueDefinition.new(pos: v_loc, definition_pos: defn_loc, description: description, name: enum_value, directives: v_directives, filename: @filename, source: self)
          end
          expect_token :RCURLY
          list
        else
          EMPTY_ARRAY
        end
      end

      def parse_union_members
        if at?(:EQUALS)
          expect_token :EQUALS
          if at?(:PIPE)
            advance_token
          end
          list = [parse_type_name]
          while at?(:PIPE)
            advance_token
            list << parse_type_name
          end
          list
        else
          EMPTY_ARRAY
        end
      end

      def parse_implements
        if at?(:IMPLEMENTS)
          advance_token
          list = []
          while true
            advance_token if at?(:AMP)
            break unless at?(:IDENTIFIER)
            list << parse_type_name
          end
          list
        else
          EMPTY_ARRAY
        end
      end

      def parse_field_definitions
        return EMPTY_ARRAY unless at?(:LCURLY)
        advance_token
        if !@tolerant
          list = []
          while !at?(:RCURLY)
            list << parse_field_definition
          end
          expect_token(:RCURLY)
          return list
        end
        list, = parse_container_elements(
          closer: :RCURLY,
          bail: [],
          restart: DEFINITION_FIELD_START_TOKENS,
        ) { parse_field_definition }
        expect_closer(:RCURLY) if at?(:RCURLY)
        list
      end

      def parse_field_definition
        loc = pos
        description = if at?(:STRING); string_value; end
        defn_loc = pos
        name = parse_name
        arguments_definition = parse_argument_definitions
        expect_token(:COLON)
        type = self.type
        directives = parse_directives
        FieldDefinition.new(pos: loc, definition_pos: defn_loc, description: description, name: name, arguments: arguments_definition, type: type, directives: directives, filename: @filename, source: self)
      end

      def parse_argument_definitions
        if at?(:LPAREN)
          advance_token
          if !@tolerant
            list = []
            while !at?(:RPAREN)
              list << parse_input_value_definition
            end
            expect_token(:RPAREN)
            return list
          end
          list, = parse_container_elements(
            closer: :RPAREN,
            bail: [:RCURLY],
            restart: DEFINITION_FIELD_START_TOKENS,
          ) { parse_input_value_definition }
          expect_closer(:RPAREN) if at?(:RPAREN)
          list
        else
          EMPTY_ARRAY
        end
      end

      def parse_input_value_definition
        loc = pos
        description = if at?(:STRING); string_value; end
        defn_loc = pos
        name = parse_name
        expect_token :COLON
        type = self.type
        default_value = if at?(:EQUALS)
          advance_token
          value
        else
          nil
        end
        directives = parse_directives
        InputValueDefinition.new(pos: loc, definition_pos: defn_loc, description: description, name: name, type: type, default_value: default_value, directives: directives, filename: @filename, source: self)
      end

      def type
        parsed_type = case token_name
        when :IDENTIFIER
          parse_type_name
        when :LBRACKET
          list_type
        else
          nil
        end

        if at?(:BANG) && parsed_type
          parsed_type = Nodes::NonNullType.new(pos: pos, of_type: parsed_type, source: self)
          expect_token(:BANG)
        end
        parsed_type
      end

      def list_type
        loc = pos
        expect_token(:LBRACKET)
        inner_type = self.type
        parsed_list_type = if inner_type
          Nodes::ListType.new(pos: loc, of_type: inner_type, source: self)
        else
          nil
        end
        expect_token(:RBRACKET)
        parsed_list_type
      end

      def parse_operation_type
        val = if at?(:QUERY)
          "query"
        elsif at?(:MUTATION)
          "mutation"
        elsif at?(:SUBSCRIPTION)
          "subscription"
        else
          expect_one_of([:QUERY, :MUTATION, :SUBSCRIPTION])
        end
        advance_token
        val
      end

      def selection_set
        loc = pos
        missing_open = nil
        if !at?(:LCURLY)
          unless @tolerant
            expect_token(:LCURLY)
          end
          err = GraphQL::ParseError.new(
            expected_token_message(:LCURLY),
            @lexer.line_number,
            @lexer.column_number,
            @graphql_str,
            filename: @filename,
          )
          record_diagnostic(err)
          missing_open = missing_token_node(:LCURLY, err.message)
        else
          advance_token
        end

        selections, status = parse_container_elements(
          closer: :RCURLY,
          bail: [:RPAREN, :RBRACKET],
          restart: SELECTION_START_TOKENS,
        ) { parse_selection }

        case status
        when :ok
          expect_closer(:RCURLY)
        when :ok_consumed
          # resync already consumed the RCURLY
          nil
        when :bail, :eof
          # Missing RCURLY already recorded; keep whatever parsed so far.
          nil
        end

        if missing_open
          [missing_open] + selections
        else
          selections
        end
      end

      private

      def parse_selection
        if at?(:ELLIPSIS)
          loc = pos
          advance_token
          case token_name
          when :ON, :DIR_SIGN, :LCURLY
            if_type = if at?(:ON)
              advance_token
              parse_type_name
            else
              nil
            end

            directives = parse_directives

            Nodes::InlineFragment.new(pos: loc, type: if_type, directives: directives, selections: selection_set, filename: @filename, source: self)
          else
            name = parse_name_without_on
            directives = parse_directives

            FragmentSpread.new(pos: loc, name: name, directives: directives, filename: @filename, source: self)
          end
        else
          loc = pos
          name = parse_name

          field_alias = nil

          if at?(:COLON)
            advance_token
            field_alias = name
            name = parse_name
          end

          arguments = at?(:LPAREN) ? parse_arguments : nil
          directives = at?(:DIR_SIGN) ? parse_directives : nil
          child_selection_set = at?(:LCURLY) ? selection_set : nil

          Nodes::Field.new(pos: loc, field_alias: field_alias, name: name, arguments: arguments, directives: directives, selections: child_selection_set, filename: @filename, source: self)
        end
      end

      def parse_name
        case token_name
        when :IDENTIFIER
          expect_token_value(:IDENTIFIER)
        when :SCHEMA
          advance_token
          "schema"
        when :SCALAR
          advance_token
          "scalar"
        when :IMPLEMENTS
          advance_token
          "implements"
        when :INTERFACE
          advance_token
          "interface"
        when :UNION
          advance_token
          "union"
        when :ENUM
          advance_token
          "enum"
        when :INPUT
          advance_token
          "input"
        when :DIRECTIVE
          advance_token
          "directive"
        when :TYPE
          advance_token
          "type"
        when :QUERY
          advance_token
          "query"
        when :MUTATION
          advance_token
          "mutation"
        when :SUBSCRIPTION
          advance_token
          "subscription"
        when :TRUE
          advance_token
          "true"
        when :FALSE
          advance_token
          "false"
        when :FRAGMENT
          advance_token
          "fragment"
        when :REPEATABLE
          advance_token
          "repeatable"
        when :NULL
          advance_token
          "null"
        when :ON
          advance_token
          "on"
        when :EXTEND
          advance_token
          "extend"
        else
          expect_token(:NAME)
        end
      end

      def parse_name_without_on
        if at?(:ON)
          expect_token(:IDENTIFIER)
        else
          parse_name
        end
      end

      def parse_type_name
        TypeName.new(pos: pos, name: parse_name, filename: @filename, source: self)
      end

      def parse_directives
        if at?(:DIR_SIGN)
          dirs = []
          while at?(:DIR_SIGN)
            loc = pos
            advance_token
            name = parse_name
            arguments = parse_arguments

            dirs << Nodes::Directive.new(pos: loc, name: name, arguments: arguments, filename: @filename, source: self)
          end
          dirs
        else
          EMPTY_ARRAY
        end
      end

      def parse_arguments
        return EMPTY_ARRAY unless at?(:LPAREN)
        advance_token
        if !@tolerant
          args = []
          while !at?(:RPAREN)
            args << parse_argument
          end
          if args.empty?
            expect_token(:ARGUMENT_NAME) # At least one argument is required
          end
          expect_token(:RPAREN)
          return args
        end

        args, argument_status = parse_container_elements(
          closer: :RPAREN,
          bail: [:RCURLY, :RBRACKET],
          restart: NAME_KEYWORD_TOKENS,
        ) { parse_argument }
        # A nested value bailed on RCURLY: leave it for the selection set
        # (the missing RPAREN/RBRACKET was already diagnosed) and return what
        # we parsed rather than retrying in place.
        if argument_status == :bail
          return args
        end
        if args.empty? && at?(:RPAREN)
          # Empty `()` is invalid; report it but don't add a MissingToken.
          err = GraphQL::ParseError.new(
            expected_token_message(:ARGUMENT_NAME),
            @lexer.line_number,
            @lexer.column_number,
            @graphql_str,
            filename: @filename,
          )
          record_diagnostic(err)
        end
        if at?(:RPAREN)
          advance_token
        end
        args
      end

      def parse_argument
        loc = pos
        name = parse_name
        expect_token(:COLON)
        Nodes::Argument.new(pos: loc, name: name, value: value, filename: @filename, source: self)
      end

      def string_value
        token_value = @lexer.string_value
        expect_token :STRING
        token_value
      end

      def value
        case token_name
        when :INT
          expect_token_value(:INT).to_i
        when :FLOAT
          expect_token_value(:FLOAT).to_f
        when :STRING
          string_value
        when :TRUE
          advance_token
          true
        when :FALSE
          advance_token
          false
        when :NULL
          advance_token
          NullValue.new(pos: pos, name: "null", filename: @filename, source: self)
        when :IDENTIFIER
          Nodes::Enum.new(pos: pos, name: expect_token_value(:IDENTIFIER), filename: @filename, source: self)
        when :LBRACKET
          list_start = pos
          advance_token
          if !@tolerant
            list = []
            while !at?(:RBRACKET)
              list << value
            end
            expect_token(:RBRACKET)
            return list
          end
          list, status = parse_container_elements(
            closer: :RBRACKET,
            bail: [:RPAREN, :RCURLY],
            restart: VALUE_START_TOKENS,
          ) { value }
          case status
          when :ok
            expect_closer(:RBRACKET)
          when :bail, :eof
            # Missing RBRACKET already recorded; keep parsed elements.
            nil
          end
          list
        when :LCURLY
          start = pos
          advance_token
          if !@tolerant
            args = []
            while !at?(:RCURLY)
              loc = pos
              n = parse_name
              expect_token(:COLON)
              args << Argument.new(pos: loc, name: n, value: value, filename: @filename, source: self)
            end
            expect_token(:RCURLY)
            return InputObject.new(pos: start, arguments: args, filename: @filename, source: self)
          end
          args, = parse_container_elements(
            closer: :RCURLY,
            bail: [:RPAREN, :RBRACKET],
            restart: NAME_KEYWORD_TOKENS,
          ) do
            loc = pos
            n = parse_name
            expect_token(:COLON)
            Argument.new(pos: loc, name: n, value: value, filename: @filename, source: self)
          end
          expect_closer(:RCURLY) if at?(:RCURLY)
          InputObject.new(pos: start, arguments: args, filename: @filename, source: self)
        when :VAR_SIGN
          loc = pos
          advance_token
          VariableIdentifier.new(pos: loc, name: parse_name, filename: @filename, source: self)
        when :SCHEMA
          advance_token
          Nodes::Enum.new(pos: pos, name: "schema", filename: @filename, source: self)
        when :SCALAR
          advance_token
          Nodes::Enum.new(pos: pos, name: "scalar", filename: @filename, source: self)
        when :IMPLEMENTS
          advance_token
          Nodes::Enum.new(pos: pos, name: "implements", filename: @filename, source: self)
        when :INTERFACE
          advance_token
          Nodes::Enum.new(pos: pos, name: "interface", filename: @filename, source: self)
        when :UNION
          advance_token
          Nodes::Enum.new(pos: pos, name: "union", filename: @filename, source: self)
        when :ENUM
          advance_token
          Nodes::Enum.new(pos: pos, name: "enum", filename: @filename, source: self)
        when :INPUT
          advance_token
          Nodes::Enum.new(pos: pos, name: "input", filename: @filename, source: self)
        when :DIRECTIVE
          advance_token
          Nodes::Enum.new(pos: pos, name: "directive", filename: @filename, source: self)
        when :TYPE
          advance_token
          Nodes::Enum.new(pos: pos, name: "type", filename: @filename, source: self)
        when :QUERY
          advance_token
          Nodes::Enum.new(pos: pos, name: "query", filename: @filename, source: self)
        when :MUTATION
          advance_token
          Nodes::Enum.new(pos: pos, name: "mutation", filename: @filename, source: self)
        when :SUBSCRIPTION
          advance_token
          Nodes::Enum.new(pos: pos, name: "subscription", filename: @filename, source: self)
        when :FRAGMENT
          advance_token
          Nodes::Enum.new(pos: pos, name: "fragment", filename: @filename, source: self)
        when :REPEATABLE
          advance_token
          Nodes::Enum.new(pos: pos, name: "repeatable", filename: @filename, source: self)
        when :ON
          advance_token
          Nodes::Enum.new(pos: pos, name: "on", filename: @filename, source: self)
        when :EXTEND
          advance_token
          Nodes::Enum.new(pos: pos, name: "extend", filename: @filename, source: self)
        else
          expect_token(:VALUE)
        end
      end

      def at?(expected_token_name)
        @token_name == expected_token_name
      end

      def expect_token(expected_token_name)
        unless @token_name == expected_token_name
          raise GraphQL::ParseError.new(
            expected_token_message(expected_token_name),
            @lexer.line_number,
            @lexer.column_number,
            @graphql_str,
            filename: @filename,
          )
        end
        advance_token
      end

      def expected_token_message(expected_token_name)
        token_display = @token_name == false ? "not end of file" : "actual: #{@token_name} (#{debug_token_value.inspect})"
        "Expected #{expected_token_name}, #{token_display} at [#{@lexer.line_number}, #{@lexer.column_number}]"
      end

      def expect_one_of(token_names)
        token_display = "#{token_name || "NOTHING"} (#{debug_token_value.inspect})"
        raise GraphQL::ParseError.new(
          "Expected one of #{token_names.join(", ")}, actual: #{token_display} at [#{@lexer.line_number}, #{@lexer.column_number}]",
          @lexer.line_number,
          @lexer.column_number,
          @graphql_str,
          filename: @filename,
        )
      end

      def raise_parse_error(message)
        message += " at [#{@lexer.line_number}, #{@lexer.column_number}]"
        raise GraphQL::ParseError.new(
          message,
          @lexer.line_number,
          @lexer.column_number,
          @graphql_str,
          filename: @filename,
        )

      end

      # Build a ParseError at the lexer's current position without modifying
      # the message (used by the recovery parser, where messages already match
      # what strict parsing would produce).
      def parse_error_at_current(message)
        GraphQL::ParseError.new(
          message,
          @lexer.line_number,
          @lexer.column_number,
          @graphql_str,
          filename: @filename,
        )
      end

      # --- Fault-tolerant recovery support ----------------------------------

      # Token sets used while resyncing after a syntax error.
      OPENER_FOR = { :RCURLY => :LCURLY, :RPAREN => :LPAREN, :RBRACKET => :LBRACKET }
      CLOSERS = OPENER_FOR.keys.freeze
      OPENERS = OPENER_FOR.values.freeze
      NAME_KEYWORD_TOKENS = [
        :IDENTIFIER, :SCHEMA, :SCALAR, :IMPLEMENTS, :INTERFACE, :UNION, :ENUM,
        :INPUT, :DIRECTIVE, :TYPE, :QUERY, :MUTATION, :SUBSCRIPTION, :TRUE,
        :FALSE, :FRAGMENT, :REPEATABLE, :NULL, :ON, :EXTEND,
      ].freeze
      DEFINITION_START_TOKENS = (
        NAME_KEYWORD_TOKENS + [:LCURLY, :STRING, :EXTEND, :ELLIPSIS]
      ).freeze
      SELECTION_START_TOKENS = (NAME_KEYWORD_TOKENS + [:ELLIPSIS]).freeze
      DEFINITION_FIELD_START_TOKENS = (NAME_KEYWORD_TOKENS + [:STRING]).freeze
      VALUE_START_TOKENS = (
        NAME_KEYWORD_TOKENS + [:INT, :FLOAT, :STRING, :TRUE, :FALSE, :NULL,
          :LBRACKET, :LCURLY, :VAR_SIGN]
      ).freeze

      private

      def parse_variable_definition
        loc = pos
        expect_token(:VAR_SIGN)
        @current_variable_name = var_name = parse_name
        expect_token(:COLON)
        var_type = self.type
        if var_type.nil?
          if @tolerant
            message = "Missing type definition for variable: $#{var_name} at [#{@lexer.line_number}, #{@lexer.column_number}]"
            raise parse_error_at_current(message)
          else
            raise_parse_error("Missing type definition for variable: $#{var_name}")
          end
        end
        default_value = if at?(:EQUALS)
          advance_token
          value
        end

        directives = parse_directives

        Nodes::VariableDefinition.new(
          pos: loc,
          name: var_name,
          type: var_type,
          default_value: default_value,
          directives: directives,
          filename: @filename,
          source: self
        )
      end

      def current_pos
        if @lexer.finished?
          @lexer.prev_token_end_pos
        else
          pos
        end
      end

      def record_diagnostic(err)
        key = [err.class, err.message, err.line, err.col]
        if !@diagnostic_keys&.include?(key)
          (@diagnostic_keys ||= []) << key
          @diagnostics << err
        end
        nil
      end

      def syntax_error_node(start_pos, message, end_pos: current_pos)
        end_pos = start_pos if end_pos < start_pos
        Nodes::SyntaxError.new(
          pos: start_pos,
          end_pos: end_pos,
          message: message,
          filename: @filename,
          source: self
        )
      end

      def missing_token_node(expected, message, position: current_pos)
        Nodes::MissingToken.new(
          pos: position,
          expected: expected.to_s,
          message: message,
          filename: @filename,
          source: self
        )
      end

      # Consume tokens until a reliable synchronization point is reached.
      #
      # The current token is always treated as part of the broken region (it
      # was being parsed when the error was raised). String tokens are atomic,
      # so punctuation inside a string can never become a sync point.
      #
      # @return [Symbol] :stop (found `stop`), :bail (found an enclosing closer
      #   that doesn't belong to this container), :restart (found `restart`
      #   after skipping junk), :junk (ran out of input), :eof
      def resync(stop:, bail:, restart:, error_start:)
        skipped_any = false
        open_stack = []
        loop do
          if @lexer.finished?
            return skipped_any ? :junk : :eof
          end
          tok = @token_name
          if open_stack.empty? && stop.include?(tok)
            # The very first token may itself be the container's closer
            # (eg an element failed immediately before `)`); consume it.
            advance_token
            return :stop
          end
          if open_stack.empty? && bail.include?(tok)
            # Closer for a different container: leave it for that container.
            return :bail
          end
          if open_stack.empty? && restart.include?(tok)
            if skipped_any
              return :restart_with_junk
            else
              # The very token that failed is itself a restart candidate
              # (eg a partial keyword). Consume it so recovery progresses.
              advance_token
              return :junk
            end
          end

          if OPENERS.include?(tok)
            open_stack << tok
          elsif CLOSERS.include?(tok)
            if open_stack.empty?
              advance_token
              return :unmatched
            elsif open_stack.last != OPENER_FOR[tok]
              # An unexpected closer while nested junk is open: it belongs to
              # an enclosing container, so bail out without consuming it.
              return :bail
            end
            open_stack.pop
          end

          skipped_any = true
          advance_token
        end
      end

      # Expect a container-closing token. In recovery mode a missing closer
      # produces a {Nodes::MissingToken} and a diagnostic instead of raising,
      # and the token is left unconsumed for the caller's resync logic.
      #
      # @return [Symbol] :ok when the closer was consumed, otherwise :eof or
      #   :bail (unexpected closer encountered)
      def expect_closer(expected_token)
        if at?(expected_token)
          advance_token
          :ok
        elsif !@tolerant
          expect_token(expected_token)
          :ok
        else
          err = GraphQL::ParseError.new(
            expected_token_message(expected_token),
            @lexer.line_number,
            @lexer.column_number,
            @graphql_str,
            filename: @filename,
          )
          record_diagnostic(err)
          if @lexer.finished?
            :eof
          else
            :bail
          end
        end
      end

      # Parse the repeated elements of a container (selections, arguments, ...)
      # with error recovery. `parse_one` must parse exactly one element.
      #
      # @return [Array(Array, Symbol)] the parsed elements and one of :ok
      #   (closer still present for the caller to consume), :eof or :bail
      #   (a closer for a different container was hit)
      def parse_container_elements(closer:, bail:, restart:, stop: [closer], &parse_one)
        elements = []
        if !@tolerant
          while !at?(closer)
            elements << parse_one.call
          end
          return [elements, :ok]
        end

        loop do
          if at?(closer)
            return [elements, :ok]
          end
          if @lexer.finished?
            err = GraphQL::ParseError.new(
              expected_token_message(closer),
              @lexer.line_number,
              @lexer.column_number,
              @graphql_str,
              filename: @filename,
            )
            record_diagnostic(err)
            elements << missing_token_node(closer, err.message)
            return [elements, :eof]
          end
          if bail.include?(@token_name)
            err = GraphQL::ParseError.new(
              expected_token_message(closer),
              @lexer.line_number,
              @lexer.column_number,
              @graphql_str,
              filename: @filename,
            )
            record_diagnostic(err)
            elements << missing_token_node(closer, err.message)
            return [elements, :bail]
          end

          error_start = current_pos
          begin
            elements << parse_one.call
          rescue GraphQL::ParseError => err
            record_diagnostic(err)
            status = resync(stop: stop, bail: bail, restart: restart, error_start: error_start)
            case status
            when :restart, :restart_with_junk
              if status == :restart_with_junk
                elements << syntax_error_node(error_start, err.message)
              end
              next
            when :stop
              # closer was consumed by resync; mark it missing and finish
              elements << missing_token_node(closer, err.message)
              return [elements, :ok_consumed]
            when :bail, :eof, :junk
              elements << syntax_error_node(error_start, err.message)
              elements << missing_token_node(closer, err.message) unless status == :junk
              return [elements, status == :junk ? :eof : status]
            end
          end
        end
      end

      # Only use when we care about the expected token's value
      def expect_token_value(tok)
        token_value = @lexer.token_value
        if @dedup_identifiers
          token_value = -token_value
        end
        expect_token(tok)
        token_value
      end

      # token_value works for when the scanner matched something
      # which is usually fine and it's good for it to be fast at that.
      def debug_token_value
        @lexer.debug_token_value(token_name)
      end
      class SchemaParser < Parser
        def initialize(*args, **kwargs)
          super
          @dedup_identifiers = true
        end
      end
    end
  end
end
