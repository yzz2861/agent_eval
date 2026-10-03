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
        t.pattern(t.escape(payload, also_escape: /[\/\?#\&\=%]/).gsub(?%, "%%"))
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

      # duplicate capture names mapped to their on_duplicate strategy
      # @!visibility private
      def duplicate_strategies
        @duplicate_strategies ||= {}
      end

      # duplicate capture names mapped to the occurrence counts they may expand to
      # @!visibility private
      def duplicate_counts
        @duplicate_counts ||= {}
      end

      # all the known keys
      # @!visibility private
      def keys
        @keys ||= []
      end

      # add a tree for expansion
      # @!visibility private
      def add(ast, on_duplicate: nil)
        translated = translate(ast)
        translated.each do |keys, pattern, filter|
          self.keys.concat(keys).uniq!
          mappings[keys.sort] ||= [keys, pattern, filter]
        end
        register_duplicates(translated, on_duplicate) if on_duplicate && on_duplicate != :error
        translated
      end

      # remembers occurrence counts and the strategy for repeated capture names
      # @!visibility private
      def register_duplicates(translated, strategy)
        counts = {}
        translated.each do |keys, _, _|
          keys.tally.each { |name, count| (counts[name] ||= []) << count }
        end
        counts.each do |name, list|
          list.uniq!
          next unless list.any? { |count| count > 1 }
          if duplicate_strategies.key?(name) && duplicate_strategies[name] != strategy
            raise ArgumentError, "conflicting on_duplicate strategies for capture #{name.inspect}"
          end
          duplicate_strategies[name] = strategy
          duplicate_counts[name]     = ((duplicate_counts[name] || []) | list).sort
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
        validate_duplicates(values) unless duplicate_strategies.empty?
        adjusted = values.each_with_object({}){ |(key, value), new_hash|
          new_hash[value.instance_of?(Array) ? [key] * value.length : key] = value }
        keys, pattern, filters = mappings.fetch(adjusted.keys.flatten.sort) { duplicate_mapping(adjusted) || error_for(values) }
        filters.each { |key, filter| adjusted[key] &&= escape(adjusted[key], also_escape: filter) }
        pattern % (adjusted[keys] || adjusted.values_at(*keys))
      end

      # Checks values for repeated capture names against their on_duplicate
      # strategy, raising an ExpandError pointing at the offending occurrence.
      # @!visibility private
      def validate_duplicates(values)
        duplicate_strategies.each do |name, strategy|
          next unless values.key? name
          value  = values[name]
          counts = duplicate_counts[name]
          if value.instance_of? Array
            unless counts.include? value.length
              raise error_class, "cannot expand #{name.inspect} with #{value.length} values, pattern expects #{counts.join(' or ')} occurrences"
            end
            next unless strategy == :check
            value.each_with_index do |element, index|
              next if element == value.first
              raise error_class, "values for #{name.inspect} must all be equal (on_duplicate: :check), but occurrence #{index + 1} is #{element.inspect} and occurrence 1 is #{value.first.inspect}"
            end
          elsif strategy == :collect
            raise error_class, "cannot expand #{name.inspect} with a single value (on_duplicate: :collect expects an Array of #{counts.join(' or ')} values)"
          end
        end
      end

      # Finds a mapping for scalar values of repeated capture names by treating
      # them as if they occurred at every position (valid for on_duplicate:
      # :check, the only strategy allowing scalars).
      # @!visibility private
      def duplicate_mapping(adjusted)
        return if duplicate_strategies.empty?
        signature = adjusted.keys.flatten.sort
        candidates = [signature]
        duplicate_strategies.each_key do |name|
          next unless adjusted.key? name
          candidates += candidates.flat_map do |sig|
            duplicate_counts[name].filter_map { |count| (sig + [name] * (count - 1)).sort if count > 1 }
          end
        end
        candidates.each { |sig| return mappings[sig] if mappings.key? sig }
        nil
      end

      # @see Mustermann::Pattern#expandable?
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
    end
  end
end
