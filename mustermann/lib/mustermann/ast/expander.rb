# frozen_string_literal: true
require 'mustermann/ast/translator'
require 'mustermann/ast/compiler'

module Mustermann
  module AST
    # Looks at an AST, remembers the important bits of information to do an
    # ultra fast expansion.
    #
    # @!visibility private
    class Expander < Translator
      raises ExpandError

      translate Array do |*args, **options|
        inject(t.pattern) do |pattern, element|
          t.add_to(pattern, t(element, *args, **options))
        end
      end

      translate :capture do |**options|
        t.for_capture(node, **options)
      end

      translate :named_splat, :splat do
        t.pattern + t.for_capture(node)
      end

      translate :expression do
        t(payload, allow_reserved: operator.allow_reserved)
      end

      translate :root, :group do
        t(payload)
      end

      translate :char do
        t.pattern(t.escape(payload, also_escape: /[\/\?#\&=%]/).gsub(?%, "%%"))
      end

      translate :separator do
        t.pattern(payload.gsub(?%, "%%"))
      end

      translate :with_look_ahead do
        t.add_to(t(head), t(payload))
      end

      translate :optional do
        nested = t(payload)
        nested += t.pattern unless nested.any? { |n| n.first.empty? }
        nested
      end

      translate :union do
        payload.map { |e| t(e) }.inject(:+)
      end

      # helper method for captures
      # @!visibility private
      def for_capture(node, **options)
        name = node.name.to_sym
        pattern('%s', name, name => /(?!#{pattern_for(node, **options)})./)
      end

      # maps sorted key list to sprintf patterns and filters
      # @!visibility private
      def mappings
        @mappings ||= {}
      end

      # all the known keys
      # @!visibility private
      def keys
        @keys ||= []
      end

      # add a tree for expansion
      # @!visibility private
      def add(ast, duplicate_captures: :raise)
        translate(ast).each do |keys, pattern, filter|
          self.keys.concat(keys).uniq!
          sorted = keys.sort
          unless mappings.include?(sorted)
            mappings[sorted] = [keys, pattern, filter, duplicate_captures || :raise, keys.tally]
          end
        end
      end

      # helper method for getting a capture's pattern.
      # @!visibility private
      def pattern_for(node, **options)
        Compiler.new.decorator_for(node).pattern(**options)
      end

      # @see Mustermann::Pattern#expand
      # @!visibility private
      def expand(values)
        adjusted, occurrences = adjust_values(values)
        keys, pattern, filters, strategy, multiplicity =
          find_mapping(adjusted) || broadcast_scalars(adjusted, occurrences) || length_mismatch(adjusted) || error_for(values)
        check_duplicates!(occurrences, multiplicity, strategy)
        filters.each do |key, filter|
          occurrences[key]&.each_with_index do |value, index|
            occurrences[key][index] = value && escape(value, also_escape: filter)
          end
        end
        position  = Hash.new(0)
        arguments = keys.map { |key| value = occurrences[key][position[key]]; position[key] += 1; value }
        pattern % arguments
      end

      # @see Mustermann::Expander#expandable?
      # @!visibility private
      def expandable?(values)
        values = values.keys if values.respond_to? :keys
        values = values.sort if values.respond_to? :sort
        mappings.include? values
      end

      # @see Mustermann::Expander#with_rest
      # @!visibility private
      def expandable_keys(keys)
        mappings.keys.select { |k| (k - keys).empty? }.max_by(&:size) || keys
      end

      # helper method for raising an error for unexpandable values
      # @!visibility private
      def error_for(values)
        expansions = mappings.keys.map(&:inspect).join(" or ")
        raise error_class, "cannot expand with keys %p, possible expansions: %s" % [values.keys.sort, expansions]
      end

      # @see Mustermann::AST::Translator#expand
      # @!visibility private
      def escape(string, *args, **options)
        return super unless string.respond_to?(:=~)

        # URI::Parser is pretty slow, let's not send every string to it, even if it's unnecessary
        string =~ /\A\w*\Z/ ? string : super
      end

      # Turns a sprintf pattern into our secret internal data structure.
      # @!visibility private
      def pattern(string = EMPTY_STRING, *keys, **filters)
        [[keys, string, filters]]
      end

      # Creates the product of two of our secret internal data structures.
      # @!visibility private
      def add_to(list, result)
        list << [[], EMPTY_STRING] if list.empty?
        list.inject([]) { |l, (k1, p1, f1)| l + result.map { |k2, p2, f2| [k1+k2, p1+p2, f1.merge(f2)] } }
      end

      private

      # Expands lists into repeated keys and keeps ordered value lists per key.
      # @!visibility private
      def adjust_values(values)
        adjusted = {}
        occurrences = {}
        values.each do |key, value|
          if value.instance_of?(Array)
            adjusted[[key] * value.length] = value unless value.empty?
            occurrences[key] = value.dup
          else
            adjusted[key] = value
            occurrences[key] = [value]
          end
        end
        [adjusted, occurrences]
      end

      # Finds the variant for the exact (possibly list-expanded) sorted keys.
      # @!visibility private
      def find_mapping(adjusted)
        mappings[adjusted.keys.flatten.sort]
      end

      # Raises a precise error when a list overshoots all variants for its key.
      # @!visibility private
      def length_mismatch(adjusted)
        adjusted.each_key do |key|
          next unless key.is_a?(Array)
          name = key.first
          available = mappings.values.map { |entry| entry[4].fetch(name, 0) }.max
          next if available.nil? || key.length <= available
          raise error_class,
            "cannot expand %p: expected %d value(s) for %d occurrence(s) of %p, got %d" %
              [name, available, available, name, key.length]
        end
        nil
      end

      # Tries variants whose repeated occurrences are all fed by scalar values.
      # @!visibility private
      def broadcast_scalars(adjusted, occurrences)
        wanted = adjusted.keys.flatten.tally
        candidates = mappings.values.select do |_keys, _pattern, _filter, _strategy, multiplicity|
          multiplicity.all? do |key, count|
            given = wanted.fetch(key, 0)
            given == count || (given == 1 && occurrences[key]&.length == 1)
          end && wanted.all? { |key, count| multiplicity.fetch(key, 0) >= count }
        end
        selected = candidates.max_by { |entry| entry[4].values.sum }
        return unless selected
        _keys, _pattern, _filter, _strategy, multiplicity = selected
        multiplicity.each do |key, count|
          occurrences[key] = Array.new(count, occurrences[key].first) if count > 1 && wanted[key] == 1
        end
        selected
      end

      # Validates lists given for repeated captures against the pattern strategy.
      # @!visibility private
      def check_duplicates!(occurrences, multiplicity, strategy)
        multiplicity.each do |key, count|
          next unless count > 1
          values = occurrences[key]
          next if strategy != :equal
          distinct = values.uniq
          next if distinct.size <= 1
          positions = values.each_with_index.group_by(&:first).map { |_, group| group.map { |_, i| i + 1 } }
          raise error_class,
            "cannot expand %p with duplicate_captures: :equal: occurrences %s of %p would have different values" %
              [key, positions.map { |group| group.join(' and ') }.join(' vs '), key]
        end
      end
    end
  end
end
