# frozen_string_literal: true

module GraphQL
  module Language
    # A fault-tolerant parser.
    #
    # Unlike {Parser}, which raises the first {GraphQL::ParseError} it finds,
    # this parser always returns a partial document. Broken spans are represented
    # in the AST with {Nodes::SyntaxErrorNode} and {Nodes::MissingNode},
    # and each problem is also reported as a {GraphQL::ParseError} in the
    # result's `diagnostics`.
    #
    # Recovery is based on token synchronization: after an error, tokens are
    # discarded until a reliable grammar position is reached. Because the
    # lexer turns string literals into single tokens, punctuation inside of
    # strings (such as a `}` inside `"...}"`) can never be mistaken for a
    # synchronization point.
    class RecoveryParser < Parser
      # The result of a fault-tolerant parse.
      class Result
        # @return [Nodes::Document] The partial document. It may contain {Nodes::SyntaxErrorNode} and {Nodes::MissingNode}.
        attr_reader :document

        # @return [Array<GraphQL::ParseError>] All syntax problems found during parsing, ordered by position.
        attr_reader :diagnostics

        def initialize(document, diagnostics)
          @document = document
          @diagnostics = diagnostics
        end

        # @return [Boolean] True when no syntax diagnostics were produced
        def valid?
          @diagnostics.empty?
        end
      end

      class << self
        # Parse `graphql_str` without raising on syntax errors.
        # @return [Result]
        def parse_with_recovery(graphql_str, filename: nil, trace: Tracing::NullTrace, max_tokens: nil)
          self.new(graphql_str, filename: filename, trace: trace, max_tokens: max_tokens).parse_with_recovery
        end
      end

      def initialize(graphql_str, filename: nil, trace: Tracing::NullTrace, max_tokens: nil)
        super
        @diagnostics = []
        @lookahead = nil
      end

      attr_reader :diagnostics

      # @return [Result]
      def parse_with_recovery
        @recovery_result ||= begin
          doc = @trace.parse(query_string: @graphql_str) do
            recover_document
          end
          Result.new(doc, @diagnostics.dup)
        rescue SystemStackError
          raise GraphQL::ParseError.new("This query is too large to execute.", nil, nil, @graphql_str, filename: @filename)
        end
      end

      private

      # Tokens that may begin a new top-level definition
      DEFINITION_START_TOKENS = [
        :LCURLY, :QUERY, :MUTATION, :SUBSCRIPTION, :FRAGMENT,
        :EXTEND, :SCHEMA, :SCALAR, :TYPE, :INTERFACE, :UNION,
        :ENUM, :INPUT, :DIRECTIVE, :IDENTIFIER, :STRING,
      ].freeze

      # Tokens that may begin a new selection
      SELECTION_START_TOKENS = [:IDENTIFIER, :QUERY, :MUTATION, :SUBSCRIPTION, :FRAGMENT, :ON, :ELLIPSIS].freeze

      # A fault-tolerant version of {Parser#document}
      def recover_document
        any_tokens = advance_token
        defns = []
        if any_tokens
          recovered = recover_definition { definition }
          defns.concat(recovered)
          while !@lexer.finished?
            before_pos = pos
            recovered = recover_definition { definition }
            defns.concat(recovered)
            if !@lexer.finished? && pos == before_pos && recovered.any? { |d| d.is_a?(Nodes::SyntaxErrorNode) }
              # Resynchronization did not make progress; drop this token to avoid looping.
              advance_token
            end
          end
        else
          diagnostic("Unexpected end of document", 1, 1)
        end
        Document.new(pos: 0, definitions: defns, filename: @filename, source: self)
      end

      # Run one top-level definition and resynchronize at the next definition boundary.
      # @return [Array] zero or more definition nodes (syntax problems are nodes too)
      def recover_definition
        extra_nodes = []
        defn_start = pos
        begin
          [yield]
        rescue GraphQL::ParseError => err
          record(err)
          resync_to_definition!(extra_nodes)
          extra_nodes << error_node(defn_start, err)
          extra_nodes
        end
      end

      # Discard tokens (respecting brace/paren/bracket nesting) until a token
      # that can begin another top-level definition is found at depth 0.
      def resync_to_definition!(extra_nodes)
        depth = 0
        while !@lexer.finished?
          if depth == 0 && DEFINITION_START_TOKENS.include?(token_name)
            return
          end

          case token_name
          when :LCURLY, :LPAREN, :LBRACKET
            depth += 1
          when :RCURLY, :RPAREN, :RBRACKET
            if depth > 0
              depth -= 1
            else
              # A stray closing token at the top level is itself the error;
              # surface it as a zero-width error and skip it.
              err = diagnostic("Unexpected #{token_name}", @lexer.line_number, @lexer.column_number)
              extra_nodes << Nodes::SyntaxErrorNode.new(
                message: err.message,
                pos: pos,
                end_pos: pos,
                filename: @filename,
                source: self,
              )
            end
          end
          advance_token
        end
      end

      # A fault-tolerant version of {Parser#selection_set}
      def selection_set
        unless at?(:LCURLY)
          diagnostic("Expected LCURLY, actual: #{token_name.inspect}", @lexer.line_number, @lexer.column_number)
          return []
        end
        expect_token(:LCURLY)
        selections = []
        while @token_name != :RCURLY && !@lexer.finished?
          selection_start = pos
          selection = begin
            parse_selection
          rescue GraphQL::ParseError => err
            record(err)
            resync_to_selection!
            error_node(selection_start, err)
          end
          selections << selection unless selection.nil?
          if !@lexer.finished? && @token_name != :RCURLY && pos == selection_start && selection.is_a?(Nodes::SyntaxErrorNode)
            advance_token
          end
        end
        if at?(:RCURLY)
          expect_token(:RCURLY)
        else
          missing = missing_node("RCURLY", pos)
          diagnostic("Expected RCURLY, not end of file", @lexer.line_number, @lexer.column_number)
          attach_recovered(selections.last, missing)
        end
        selections
      end

      # One selection inside a selection set (the body of the base parser's loop)
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

          # A missing closing `)` may leave the cursor on the enclosing `}`.
          arguments = at?(:LPAREN) ? parse_arguments : nil
          directives = (at?(:DIR_SIGN) && !at?(:RCURLY)) ? parse_directives : nil
          sub_selection_set = at?(:LCURLY) ? selection_set : nil

          Nodes::Field.new(pos: loc, field_alias: field_alias, name: name, arguments: arguments, directives: directives, selections: sub_selection_set, filename: @filename, source: self)
        end
      end

      def resync_to_selection!
        until @lexer.finished?
          case token_name
          when :RCURLY
            return
          when *SELECTION_START_TOKENS
            return
          end
          advance_token
        end
      end

      # A fault-tolerant version of {Parser#parse_directives}
      def parse_directives
        dirs = []
        while at?(:DIR_SIGN)
          dir_start = pos
          directive = begin
            loc = pos
            advance_token
            name = parse_name
            arguments = parse_arguments
            Nodes::Directive.new(pos: loc, name: name, arguments: arguments, filename: @filename, source: self)
          rescue GraphQL::ParseError => err
            record(err)
            resync_to_directive!
            error_node(dir_start, err)
          end
          dirs << directive
          if !@lexer.finished? && pos == dir_start && at?(:DIR_SIGN) && directive.is_a?(Nodes::SyntaxErrorNode)
            advance_token
          end
        end
        dirs
      end

      def resync_to_directive!
        until @lexer.finished?
          case token_name
          when :DIR_SIGN, :RCURLY, :LPAREN, :LCURLY
            return
          when *SELECTION_START_TOKENS
            return
          end
          advance_token
        end
      end

      # A fault-tolerant version of {Parser#parse_arguments}
      def parse_arguments
        return EMPTY_ARRAY unless at?(:LPAREN)
        opening_paren_pos = pos
        advance_token
        args = []
        while !at?(:RPAREN) && !@lexer.finished? && !at?(:RCURLY)
          arg_start = pos
          arg = begin
            loc = pos
            name = parse_name
            expect_token(:COLON)
            arg_value = value
            Nodes::Argument.new(pos: loc, name: name, value: arg_value, filename: @filename, source: self)
          rescue GraphQL::ParseError => err
            record(err)
            resync_to_argument!(opening_paren_pos)
            error_node(arg_start, err)
          end
          args << arg
          if !@lexer.finished? && !at?(:RPAREN) && pos == arg_start && arg.is_a?(Nodes::SyntaxErrorNode)
            if brace_matches_argument_context?(opening_paren_pos)
              # The resync landed on a token that closes the enclosing construct;
              # stop parsing arguments and let the caller continue.
              break
            else
              # Skip the broken token so the argument list makes progress.
              advance_token
            end
          end
        end
        if args.empty? && !at?(:RPAREN)
          # At least one argument is required
          err = diagnostic("Expected ARGUMENT_NAME, not end of file", @lexer.line_number, @lexer.column_number)
          args << missing_node("ARGUMENT_NAME", pos, message: err.message)
        end
        if at?(:RPAREN)
          expect_token(:RPAREN)
        else
          if @lexer.finished?
            missing = missing_node("RPAREN", pos)
            diagnostic("Expected RPAREN, not end of file", @lexer.line_number, @lexer.column_number)
            attach_recovered(args.last, missing)
          else
            # The list was abandoned at an enclosing closing token (for example, a `}`).
            diagnostic("Expected RPAREN, actual: #{token_name}", @lexer.line_number, @lexer.column_number)
          end
        end
        args
      end

      # Determine whether the current closing `}` closes the argument list's
      # enclosing selection (rather than an input object opened inside the list).
      # A throwaway lexer rescans the span so punctuation inside strings is not
      # counted.
      def brace_matches_argument_context?(opening_paren_pos)
        return true if at?(:RPAREN)
        return false unless at?(:RCURLY)
        span = @graphql_str.byteslice(opening_paren_pos, pos - opening_paren_pos)
        lexer = Lexer.new(span, filename: @filename)
        depth = 0
        token = lexer.advance
        while token
          case token
          when :LPAREN, :LBRACKET, :LCURLY
            depth += 1
          when :RPAREN, :RBRACKET, :RCURLY
            depth -= 1
          end
          token = lexer.advance
        end
        depth <= 1
      rescue GraphQL::ParseError
        # A malformed span (such as an unterminated string) can't be balanced; recover safely.
        false
      end

      # Resync inside an argument list. Stops before a closing paren/brace,
      # or before a new `name:` argument.
      def resync_to_argument!(opening_paren_pos)
        until @lexer.finished?
          case token_name
          when :RPAREN
            return
          when :RCURLY
            return if brace_matches_argument_context?(opening_paren_pos)
          when :IDENTIFIER, :STRING, :TRUE, :FALSE, :NULL, :QUERY, :MUTATION, :SUBSCRIPTION, :FRAGMENT, :ON, :TYPE, :INPUT, :ENUM, :SCALAR, :SCHEMA, :UNION, :INTERFACE, :DIRECTIVE, :EXTEND, :IMPLEMENTS, :REPEATABLE
            if peek_token == :COLON
              return
            end
          end
          advance_token
        end
      end

      # A fault-tolerant version of {Parser#parse_variable_definition}
      def parse_variable_definition
        defn_start = pos
        node = begin
          super
        rescue GraphQL::ParseError => err
          record(err)
          resync_to_variable_definition!
          error_node(defn_start, err)
        end
        if !@lexer.finished? && !at?(:RPAREN) && pos == defn_start && node.is_a?(Nodes::SyntaxErrorNode)
          advance_token
        end
        node
      end

      def resync_to_variable_definition!
        until @lexer.finished?
          case token_name
          when :RPAREN, :RCURLY
            return
          when :VAR_SIGN
            return
          end
          advance_token
        end
      end

      # A missing closing delimiter at EOF becomes a {Nodes::MissingNode} rather
      # than aborting the whole surrounding construct. Other missing tokens
      # raise so the enclosing recovery boundary can resynchronize.
      def expect_token(expected_token_name)
        if @lexer.finished? && CLOSING_DELIMITERS.include?(expected_token_name)
          message = "Expected #{expected_token_name}, not end of file"
          diagnostic(message, @lexer.line_number, @lexer.column_number)
          return missing_node(expected_token_name.to_s, pos, message: message)
        end
        super
      end

      CLOSING_DELIMITERS = [:RCURLY, :RPAREN, :RBRACKET].freeze

      # Look one token ahead without consuming the current token.
      def peek_token
        return false if @lexer.finished?
        @lookahead ||= begin
          current_name = @token_name
          current_pos = @lexer.pos
          name = advance_token
          next_pos = @lexer.scanner_pos
          @token_name = current_name
          @lexer.rewind_and_match!(current_pos, next_pos)
          [name, current_pos, next_pos]
        end
        @lookahead[0]
      end

      def advance_token
        @lookahead = nil
        token, lexer_error = @lexer.advance_with_recovery
        @token_name = token
        if token == :UNKNOWN_CHAR
          # The strict lexer reports stray bytes without a regex match; normalize
          # the scanner so token value accessors stay usable during recovery.
          @lexer.match_last_token!
        end
        if lexer_error
          record(lexer_error)
        end
        token
      end

      def missing_node(description, node_pos, message: nil)
        Nodes::MissingNode.new(
          description: message || description,
          pos: node_pos,
          end_pos: node_pos,
          filename: @filename,
          source: self,
        )
      end

      # Attach a syntax problem node to an enclosing valid node. If no enclosing
      # node is available (for example, an empty argument list), the problem is
      # returned as a standalone node for the caller to place in the tree.
      def attach_recovered(parent, node)
        if parent.is_a?(Nodes::AbstractNode)
          existing = parent.instance_variable_get(:@recovered_nodes)
          if existing
            existing << node
          else
            parent.instance_variable_set(:@recovered_nodes, [node])
          end
          parent.instance_variable_set(:@children, nil)
          node
        else
          node
        end
      end

      def error_node(node_start, err)
        node_end = @lexer.finished? ? @graphql_str.bytesize : pos
        Nodes::SyntaxErrorNode.new(
          message: err.message,
          pos: node_start,
          end_pos: node_end,
          filename: @filename,
          source: self,
        )
      end

      def record(err)
        if @diagnostics.empty? || [@diagnostics.last.line, @diagnostics.last.col, @diagnostics.last.message] != [err.line, err.col, err.message]
          @diagnostics << err
        end
        err
      end

      def diagnostic(message, line, col)
        err = GraphQL::ParseError.new(message, line, col, @graphql_str, filename: @filename)
        record(err)
        err
      end
    end
  end
end
