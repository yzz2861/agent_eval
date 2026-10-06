# frozen_string_literal: true
module Psych
  module Visitors
    class BlockScalar
      def self.rewrite yaml, tree, line_width, unlimited, style, indentation
        attach_parents(tree)
        document = Psych.parse(yaml)
        attach_parents(document)

        all_pairs = scalar_pairs(tree, document)
        target_pairs = all_pairs.select do |source_node, _|
          preferred_style(source_node) == style &&
            source_node.tag != '!binary' &&
            eligible?(source_node.value)
        end
        return yaml if target_pairs.empty?

        replacements = target_pairs.filter_map do |source_node, emitted_node|
          block_style = style == Psych::Nodes::Scalar::FOLDED && source_node.value.include?("\n") ?
            Psych::Nodes::Scalar::LITERAL : style
          column = block_column(yaml, source_node, emitted_node, indentation)
          block = new(source_node.value, column, line_width, unlimited, block_style)
          next unless block.valid?

          [
            character_position(yaml, emitted_node.start_line, emitted_node.start_column),
            scalar_end_position(yaml, emitted_node),
            header_prefix(source_node) + block.render
          ]
        end

        accepted = []
        replacements.each do |replacement|
          candidate = render(yaml, accepted + [replacement])
          next unless preserved?(candidate, all_pairs, target_pairs)

          accepted << replacement
        end

        render(yaml, accepted)
      end

      def self.attach_parents node, parent = nil
        node.instance_variable_set(:@psych_parent, parent)
        node.children&.each { |child| attach_parents(child, node) }
      end
      private_class_method :attach_parents

      def self.parent node
        node.instance_variable_get(:@psych_parent)
      end
      private_class_method :parent

      def self.preferred_style node
        node.instance_variable_get(:@preferred_string_style)
      end
      private_class_method :preferred_style

      def self.scalar_pairs source, emitted
        pairs = []
        source = source.children.first if source.is_a?(Psych::Nodes::Stream)
        emitted = emitted.children.first if emitted.is_a?(Psych::Nodes::Stream)
        collect(source, emitted, pairs)
        pairs
      end
      private_class_method :scalar_pairs

      def self.collect source, emitted, pairs
        if source.is_a?(Psych::Nodes::Scalar)
          pair = [source, emitted]
          pairs << pair
          return
        end

        source_children = source.children || []
        emitted_children = emitted.children || []
        source_index = 0
        emitted_index = 0

        while source_index < source_children.size
          source_child = source_children[source_index]
          if source_child.alias?
            emitted_index += 1 if emitted_children[emitted_index]
            source_index += 1
            next
          end

          emitted_child = emitted_children[emitted_index]
          break unless emitted_child
          collect(source_child, emitted_child, pairs)
          source_index += 1
          emitted_index += 1
        end
      end
      private_class_method :collect

      def self.eligible? value
        value.encoding == Encoding::UTF_8 &&
          !value.empty? &&
          !value.include?("\r")
      end
      private_class_method :eligible?

      def self.block_column yaml, source_node, emitted_node, indentation
        source_parent = parent(source_node)
        if source_parent.is_a?(Psych::Nodes::Document)
          0
        elsif source_parent.is_a?(Psych::Nodes::Mapping)
          index = source_parent.children.index(source_node)
          key_index = index && index.positive? ? index - 1 : nil
          emitted_parent = parent(emitted_node)
          emitted_key = key_index && emitted_parent.children[key_index]
          return emitted_node.start_column unless emitted_key

          key_column = emitted_key.respond_to?(:start_column) ? emitted_key.start_column : 0
          key_column.zero? ? indentation : key_column
        elsif source_parent.is_a?(Psych::Nodes::Sequence)
          line = yaml.lines[emitted_node.start_line]
          prefix = line[0...emitted_node.start_column]
          dash = prefix[/\A *-\z/] ? prefix.length - 1 : nil
          dash && prefix[(dash + 1)..].strip.empty? ? dash : [emitted_node.start_column - indentation, 0].max
        else
          emitted_node.start_column
        end
      end
      private_class_method :block_column

      def self.character_position yaml, line, column
        line_position(yaml, line) + column
      end
      private_class_method :character_position

      def self.line_position yaml, line
        position = 0
        line.times { position = yaml.index("\n", position) + 1 }
        position
      end
      private_class_method :line_position

      def self.scalar_end_position yaml, node
        end_position = character_position(yaml, node.end_line, node.end_column)
        end_position += 1 if yaml[end_position] == "\n"
        end_position
      end
      private_class_method :scalar_end_position

      def self.header_prefix node
        prefix = +""
        prefix << "&#{node.anchor} " if node.anchor
        prefix << "#{node.tag} " if node.tag
        prefix
      end
      private_class_method :header_prefix

      def self.preserved? yaml, all_pairs, target_pairs
        candidate_document = Psych.parse(yaml)
        candidate_scalars = scalar_nodes(candidate_document)
        return false unless candidate_scalars.size == all_pairs.size

        target_set = target_pairs.map(&:first)
        all_pairs.zip(candidate_scalars).all? do |(source_node, _), candidate_node|
          next true unless target_set.include?(source_node)
          candidate_node.value.b == source_node.value.b
        end
      rescue Psych::Exception
        false
      end
      private_class_method :preserved?

      def self.scalar_nodes node
        nodes = []
        walk(node) { |child| nodes << child if child.is_a?(Psych::Nodes::Scalar) }
        nodes
      end
      private_class_method :scalar_nodes

      def self.walk node, &block
        yield node
        node.children&.each { |child| walk(child, &block) }
      end
      private_class_method :walk

      def self.render yaml, replacements
        result = +""
        position = 0

        replacements.each do |start_position, end_position, replacement|
          result << yaml[position...start_position]
          result << replacement
          position = end_position
        end

        result << yaml[position..]
        result
      end
      private_class_method :render

      def initialize value, column, line_width, unlimited, style
        @value = value
        @column = column
        @line_width = line_width
        @unlimited = unlimited
        @style = style
      end

      def valid?
        self.class.send(:eligible?, @value) &&
          block_indentation <= 9 &&
          @column + body_indentation <= 9 &&
          (!folded? || foldable?)
      end

      def render
        indicator + chomping + "\n" + body
      end

      private

      def folded?
        @style == Psych::Nodes::Scalar::FOLDED
      end

      def foldable?
        !@value.include?("\n")
      end

      def lines
        @lines ||= @value.split("\n", -1)
      end

      def leading_spaces
        @leading_spaces ||= lines.map { |line|
          indentation = line[/\A[ \t]*/].to_s
          if indentation.include?("\t")
            indentation[/\A */].length + 1
          else
            indentation.length
          end
        }.max
      end

      def block_indentation
        @block_indentation ||= begin
          indentation = [1, leading_spaces].max
          needs_explicit_indentation = lines.any? do |line|
            line.match?(/\A[ \t]+\z/) ||
              line.match?(/\A[ \t]*\t/) ||
              line.match?(/ +\z/)
          end
          needs_explicit_indentation ? [2, leading_spaces].max : indentation
        end
      end

      def body_indentation
        [2, leading_spaces].max
      end

      def indicator
        indicator = +(folded? ? ">" : "|")
        indicator_indentation = [2, block_indentation].max
        indicator << indicator_indentation.to_s unless indicator_indentation == 2 && leading_spaces.zero?
        indicator
      end

      def chomping
        return "+" if @value.end_with?("\n\n")
        return "" if @value.end_with?("\n")
        "-"
      end

      def body
        body_lines = folded? ? folded_lines : lines
        prefix = " " * (@column + body_indentation)
        if @value.end_with?("\n") && !@value.end_with?("\n\n")
          body_lines[0...-1].map { |line| line.empty? ? "\n" : "#{prefix}#{line}\n" }.join
        else
          body_lines.map { |line| line.empty? ? "\n" : "#{prefix}#{line}\n" }.join
        end
      end

      def folded_lines
        return [@value] if @value.include?("\n")

        width = effective_line_width
        return [@value] if width.nil?
        width -= @column + body_indentation
        return [@value] if width <= 0

        lines = []
        position = 0

        while @value.length - position > width
          fold_at = fold_position(position, width)
          return lines + [@value[position..]] unless fold_at

          lines << @value[position...fold_at]
          position = fold_at + 1
        end

        lines << @value[position..]
        lines
      end

      def effective_line_width
        return nil if @unlimited
        @line_width.nil? || @line_width.zero? ? 80 : @line_width
      end

      def fold_position position, width
        limit = position + width
        fold_at = nil
        index = position + 1

        while (index = @value.index(" ", index))
          safe_fold = index.positive? && index + 1 < @value.length
          safe_fold &&= !special_fold_character?(@value[index - 1])
          safe_fold &&= !special_fold_character?(@value[index + 1])
          safe_fold &&= !special_fold_prefix?(@value[0...index])
          safe_fold &&= !special_fold_suffix?(@value[(index + 1)..])
          if index > limit && fold_at
            break
          elsif index > position
            fold_at = index if safe_fold
          end
          index += 1
        end

        fold_at
      end

      def special_fold_character? character
        character == "\t" || character.match?(/[\p{Symbol}\p{Punct}\p{Cntrl}]/)
      end

      def special_fold_prefix? text
        text.match?(/(?:\A| )[-:?&*]\z/)
      end

      def special_fold_suffix? text
        text.match?(/\A(?:[-:?&*!#@]|[-:?] +\z)/)
      end
    end
  end
end
