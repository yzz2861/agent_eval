# frozen_string_literal: true

require 'cgi'

module Liquid
  # A string value carrying an explicit output-safety guarantee for a
  # specific output context (HTML text, HTML attribute, or JSON string).
  #
  # SafeValues are only produced when a template is rendered with an
  # explicit output mode (see Context#output_mode). In the default mode
  # Liquid behaves exactly as before and no SafeValues are created.
  #
  # A SafeValue only vouches for the context named by its guarantee; there
  # is no generic "safe" marker. When the value is rendered into a context
  # its guarantee does not cover, it is escaped again for that context.
  class SafeValue
    OUTPUT_MODES = %i[html html_attribute json].freeze

    # Which output modes each guarantee covers. Attribute escaping escapes a
    # superset of the characters escaped for HTML text, so an
    # attribute-safe value is also safe in HTML text context.
    GUARANTEE_COVERAGE = {
      html: %i[html].freeze,
      html_attribute: %i[html html_attribute].freeze,
      json: %i[json].freeze,
    }.freeze

    attr_reader :guarantee

    def initialize(string, guarantee)
      unless GUARANTEE_COVERAGE.key?(guarantee)
        raise ArgumentError, "unknown safety guarantee: #{guarantee.inspect}"
      end

      @string    = string
      @guarantee = guarantee
    end

    def to_s
      @string
    end

    def to_str
      @string
    end

    def to_liquid
      self
    end

    def safe_for?(mode)
      GUARANTEE_COVERAGE.fetch(@guarantee).include?(mode)
    end

    def ==(other)
      to_s == (other.is_a?(SafeValue) ? other.to_s : other)
    end

    def inspect
      "#<Liquid::SafeValue #{@guarantee}: #{@string.inspect}>"
    end
  end

  # Escaping helpers for the supported output modes.
  module SafeOutput
    HTML_ATTRIBUTE_ESCAPE = {
      '&' => '&amp;',
      '>' => '&gt;',
      '<' => '&lt;',
      '"' => '&quot;',
      "'" => '&#39;',
    }.freeze
    HTML_ATTRIBUTE_ESCAPE_REGEXP = /[&<>"']/

    JSON_ESCAPE = {
      '"' => '\\"',
      '\\' => '\\\\',
      "\n" => '\n',
      "\r" => '\r',
      "\t" => '\t',
      "\b" => '\b',
      "\f" => '\f',
    }.freeze
    JSON_ESCAPE_REGEXP = /["\\\n\r\t\b\f]|[\x00-\x1f]/

    class << self
      def escape(string, mode)
        case mode
        when :html then escape_html(string)
        when :html_attribute then escape_html_attribute(string)
        when :json then escape_json(string)
        else
          raise ArgumentError, "unknown output mode: #{mode.inspect}"
        end
      end

      def escape_html(string)
        CGI.escapeHTML(string)
      end

      # Escapes everything HTML text escaping does, plus single quotes, so
      # the result is safe inside single- or double-quoted attributes.
      def escape_html_attribute(string)
        string.gsub(HTML_ATTRIBUTE_ESCAPE_REGEXP, HTML_ATTRIBUTE_ESCAPE)
      end

      # Escapes a string for embedding inside a JSON string literal (the
      # surrounding quotes are provided by the template).
      def escape_json(string)
        string.gsub(JSON_ESCAPE_REGEXP) do |char|
          JSON_ESCAPE[char] || format('\\u%04x', char.ord)
        end
      end
    end
  end
end
