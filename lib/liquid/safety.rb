# frozen_string_literal: true

require 'json'

module Liquid
  # Contextual output safety tracking.
  #
  # A value is never considered "generally safe". It can instead carry one or
  # more *guarantees*, where each guarantee is tied to a specific output
  # context (HTML text, an HTML attribute value, or a JSON string). A value is
  # emitted without re-escaping only when it carries the guarantee matching the
  # active output mode; otherwise it is escaped for that context.
  #
  # This machinery only performs escaping in the non-classic output modes.
  # The default Liquid behaviour (the +:classic+ mode) is unchanged.
  module Safety
    # Output modes. These describe where the rendered text ends up.
    CLASSIC        = :classic
    HTML_TEXT      = :html_text
    HTML_ATTRIBUTE = :html_attribute
    JSON_STRING    = :json_string

    MODES = [CLASSIC, HTML_TEXT, HTML_ATTRIBUTE, JSON_STRING].freeze

    # Aliases accepted when configuring an output mode.
    MODE_ALIASES = {
      classic: CLASSIC,
      html: HTML_TEXT,
      :'html/text' => HTML_TEXT,
      html_text: HTML_TEXT,
      text: HTML_TEXT,
      html_attribute: HTML_ATTRIBUTE,
      :'html/attribute' => HTML_ATTRIBUTE,
      attribute: HTML_ATTRIBUTE,
      attr: HTML_ATTRIBUTE,
      json: JSON_STRING,
      :'json/string' => JSON_STRING,
      json_string: JSON_STRING,
    }.freeze

    # Guarantees a string may carry. These are intentionally distinct even
    # though some escaping schemes overlap: a guarantee is a claim about a
    # specific sink, never about "all HTML".
    GUARANTEES = [HTML_TEXT_GUARANTEE = :html_text,
                  HTML_ATTRIBUTE_GUARANTEE = :html_attribute,
                  JSON_STRING_GUARANTEE = :json_string].freeze

    # Describes what a filter does to the guarantees flowing through it.
    #
    # +produces+:: guarantees that always hold for the result, regardless of
    #              the input (e.g. +escape+ always yields HTML-text-safe output).
    # +preserves+:: guarantees kept from the input. A preserved guarantee is
    #              dropped unless every named argument also carries it, so a
    #              single safe fragment can never make a concatenation safe.
    FilterSpec = Struct.new(:produces, :preserves) do
      def initialize(produces: nil, preserves: nil)
        super(Safety.wrap_guarantees(produces), Safety.wrap_guarantees(preserves))
      end
    end

    class << self
      # Normalizes a user-provided mode name to one of the MODES constants.
      def coerce_mode(mode)
        return CLASSIC if mode.nil?

        key = mode.is_a?(Symbol) ? mode : mode.to_s.downcase.tr('-', '_').to_sym
        MODE_ALIASES.fetch(key) do
          raise ArgumentError, "unknown Liquid output mode #{mode.inspect} " \
            "(expected one of #{MODES.map(&:inspect).join(', ')})"
        end
      end

      # Returns the guarantee that, if present, permits raw output in +mode+.
      def guarantee_for_mode(mode)
        case mode
        when HTML_TEXT      then HTML_TEXT_GUARANTEE
        when HTML_ATTRIBUTE then HTML_ATTRIBUTE_GUARANTEE
        when JSON_STRING    then JSON_STRING_GUARANTEE
        end
      end

      # Escapes an untrusted string for the given mode. +nil+ and non-string
      # objects are converted with +Utils.to_s+ by the caller.
      def escape_for_mode(str, mode)
        case mode
        when HTML_TEXT, HTML_ATTRIBUTE
          CGI.escapeHTML(str)
        when JSON_STRING
          json_escape(str)
        else
          str
        end
      end

      # Escapes a string so it is safe to place between the quotes of a JSON
      # string literal. The surrounding quotes are not added.
      def json_escape(str)
        JSON.generate(str, quirks_mode: true)[1...-1]
      end

      # Wraps +str+ so that it carries +guarantees+.
      def mark(str, guarantees)
        return str if str.nil?
        guarantees = wrap_guarantees(guarantees)
        return str if guarantees.empty?

        SafeValue.new(str, guarantees.freeze)
      end

      # Returns the frozen guarantee set carried by +value+, or nil.
      def guarantees(value)
        value.guarantees if value.is_a?(SafeValue)
      end

      # True when +value+ is a SafeValue carrying +guarantee+.
      def safe_for?(value, guarantee)
        (g = guarantees(value)) && g.include?(guarantee)
      end

      # Returns a copy of +value+ with every guarantee removed, recursively
      # through arrays and hashes. Used at trust boundaries (e.g. values
      # returned by Drops) so untrusted code cannot forge safety.
      def strip(value)
        case value
        when SafeValue
          value.to_str
        when Array
          value.map { |item| strip(item) }
        when Hash
          value.each_with_object({}) { |(k, v), h| h[strip(k)] = strip(v) }
        else
          value
        end
      end

      # Computes the guarantees of a filter result from the filter's spec and
      # the guarantees carried by the input and the filter arguments.
      def apply_spec(spec, input_guarantees, argument_guarantees)
        return nil unless spec

        result = spec.produces.dup
        spec.preserves.each do |guarantee|
          kept = input_guarantees.nil? ? false : input_guarantees.include?(guarantee)
          if kept
            kept = argument_guarantees.all? { |g| g&.include?(guarantee) }
          end
          result << guarantee if kept
        end
        result
      end

      def wrap_guarantees(value)
        case value
        when nil then []
        when Array then value
        else [value]
        end
      end
    end

    # A String subclass that records the output contexts in which its contents
    # are already safe. Instances are frozen; any operation that derives a new
    # string (concatenation, slicing, gsub, ...) returns a plain String and
    # therefore loses every guarantee automatically.
    class SafeValue < String
      attr_reader :guarantees

      def initialize(str, guarantees)
        super(str.to_s)
        @guarantees = guarantees.is_a?(Array) ? guarantees.freeze : Array(guarantees).freeze
        freeze
      end

      # Stays a plain, unmarked string.
      def to_str
        String.new(self)
      end

      def to_liquid
        self
      end

      def inspect
        "#<Liquid::Safety::SafeValue guarantees=#{guarantees.inspect} #{super}>"
      end
    end
  end
end
