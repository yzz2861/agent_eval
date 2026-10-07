# frozen_string_literal: true
module Slim
  class InvalidAttributeNameError < StandardError; end
  module Splat
    # @api private
    class Builder
      # https://html.spec.whatwg.org/multipage/syntax.html#attributes-2
      INVALID_ATTRIBUTE_NAME_REGEX = /[ \0"'>\/=]/
      CONFLICT_POLICIES = [:reject, :first, :last].freeze

      def initialize(options)
        @options = options
        @attrs = {}
        unless CONFLICT_POLICIES.include?(@options[:attr_conflict])
          raise ArgumentError, "Unknown attribute conflict policy #{@options[:attr_conflict].inspect}"
        end
        @options[:merge_attrs].each do |name, policy|
          unless String === policy || CONFLICT_POLICIES.include?(policy)
            raise ArgumentError, "Unknown attribute conflict policy #{policy.inspect} for attribute #{name.inspect}"
          end
        end
      end

      def code_attr(name, escape, value)
        value = value.first if Array === value && value.size == 1
        if merge_attr?(name)
          merge_code_attr(name, escape, value)
        elsif @options[:hyphen_attrs].include?(name) && Hash === value
          hyphen_attr(name, escape, value)
        elsif value != false && value != nil
          attr(name, escape_html(escape, value))
        end
      end

      def splat_attrs(splat)
        splat.each do |name, value|
          code_attr(name.to_s, true, value)
        end
      end

      def attr(name, value)
        name = name.to_s
        if name =~ INVALID_ATTRIBUTE_NAME_REGEX
          raise InvalidAttributeNameError, "Invalid attribute name '#{name}' was rendered"
        end
        return if String === attr_policy(name) && value.respond_to?(:empty?) && value.empty?
        if @attrs.key?(name)
          resolve_conflict(name, value)
        else
          @attrs[name] = value
        end
      end

      def resolve_conflict(name, value)
        existing = @attrs[name]
        case attr_policy(name)
          when :reject
            raise "Multiple #{name} attributes specified"
          when :first
            # Keep the already stored first value
          when :last
            @attrs[name] = value
          when String
            @attrs[name] = existing.to_s + attr_policy(name) + value.to_s
          else
            raise ArgumentError, "Unknown attribute conflict policy #{attr_policy(name).inspect}"
        end
      end

      def build_tag(&block)
        tag = @attrs.delete('tag').to_s
        tag = @options[:default_tag] if tag.empty?
        if block
          content = capture_block_content(&block)
          "<#{tag}#{build_attrs}>#{content}</#{tag}>"
        else
          "<#{tag}#{build_attrs} />"
        end
      end

      def build_attrs
        attrs = @options[:sort_attrs] ? @attrs.sort_by(&:first) : @attrs
        attrs.map do |k, v|
          if v == true
            if @options[:format] == :xhtml
              " #{k}=#{@options[:attr_quote]}#{@options[:attr_quote]}"
            else
              " #{k}"
            end
          else
            " #{k}=#{@options[:attr_quote]}#{v}#{@options[:attr_quote]}"
          end
        end.join
      end

      private

      def attr_policy(name)
        @options[:merge_attrs][name] || @options[:attr_conflict]
      end

      def merge_attr?(name)
        @options[:merge_attrs].key?(name)
      end

      def merge_code_attr(name, escape, value)
        policy = attr_policy(name)
        if String === policy
          if Array === value
            value = value.flatten.map(&:to_s).reject(&:empty?).join(policy)
          else
            value = value.to_s
          end
          attr(name, escape_html(escape, value)) unless value.empty?
        else
          values = Array === value ? value.flatten : [value]
          values.each do |part|
            next if part == false || part.nil?
            part = part.to_s
            attr(name, escape_html(escape, part)) unless part.empty?
          end
        end
      end

      # Captures block content using the appropriate capturing mechanism.
      #
      # If we have Slim capturing disabled and the scope defines the method `capture` (i.e. Rails)
      # we use this method to capture the content.
      #
      # Otherwise we just use normal Slim capturing (yield).
      #
      # See https://github.com/slim-template/slim/issues/591
      #     https://github.com/slim-template/slim#helpers-capturing-and-includes
      def capture_block_content(&block)
        if @options[:disable_capture] && (scope = block.binding.eval('self')).respond_to?(:capture)
          scope.capture(&block)
        else
          yield
        end
      end

      def hyphen_attr(name, escape, value)
        if Hash === value
          if @options[:hyphen_underscore_attrs]
            value.each do |n, v|
              hyphen_attr("#{name}-#{n.to_s.tr('_', '-')}", escape, v)
            end
          else
            value.each do |n, v|
              hyphen_attr("#{name}-#{n}", escape, v)
            end
          end
        else
          attr(name, escape_html(escape, value))
        end
      end

      def escape_html(escape, value)
        return value if !escape || value == true
        @options[:use_html_safe] ? Temple::Utils.escape_html_safe(value) : Temple::Utils.escape_html(value)
      end
    end
  end
end
