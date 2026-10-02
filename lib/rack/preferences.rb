# frozen_string_literal: true

module Rack
  # Rack::Preferences parses the HTTP +Prefer+ request header (RFC 7240)
  # and tracks which of the requested preferences the application has
  # explicitly applied, so that Rack::PreferenceApplied can generate an
  # accurate +Preference-Applied+ response header.
  #
  #   preferences = Rack::Preferences.parse('return=minimal, wait="10"')
  #   preferences['return']   # => 'minimal'
  #   preferences['wait']     # => '10'
  #   preferences.apply('return')
  #   preferences.applied_header # => 'return=minimal'
  #
  # Parsing is deterministic:
  #
  # * Preference and parameter names are case-insensitive and stored
  #   lowercase.
  # * If the same preference (or parameter) occurs multiple times, the
  #   first occurrence wins and subsequent occurrences are ignored
  #   (RFC 7240, Section 2). This also resolves conflicting values such
  #   as +return=minimal, return=representation+ in favor of the first.
  # * Values and extension parameter values may be quoted strings;
  #   surrounding quotes are removed and quoted-pairs are unescaped.
  # * Malformed entries are ignored.
  class Preferences
    include Enumerable

    # Matches a valid HTTP token (RFC 7230, Section 3.2.6).
    TOKEN_PATTERN = /\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+\z/

    # Split +string+ on +delimiter+, ignoring delimiters inside quoted
    # strings.
    def self.split_quoted(string, delimiter)
      parts = []
      part = +''
      quoted = false
      escaped = false

      string.each_char do |char|
        if escaped
          part << char
          escaped = false
        elsif quoted && char == '\\'
          part << char
          escaped = true
        elsif char == '"'
          part << char
          quoted = !quoted
        elsif !quoted && char == delimiter
          parts << part
          part = +''
        else
          part << char
        end
      end
      parts << part
      parts
    end

    # Remove surrounding double quotes from +value+ and unescape
    # quoted-pairs. Returns the value unchanged if it is not quoted.
    def self.unquote(value)
      if value.length >= 2 && value.start_with?('"') && value.end_with?('"')
        value[1..-2].gsub(/\\(.)/m, '\1')
      else
        value
      end
    end

    # Format a single preference for use in a header value, quoting the
    # value if it is not a valid token.
    def self.format(name, value)
      if value == true
        name
      elsif value.is_a?(String) && value.match?(TOKEN_PATTERN)
        "#{name}=#{value}"
      else
        %(#{name}="#{value.to_s.gsub(/["\\]/){|char| "\\#{char}"}}")
      end
    end

    # Parse a +Prefer+ header value into a Rack::Preferences instance.
    def self.parse(header)
      preferences = {}
      order = []

      unless header.nil?
        split_quoted(header.to_s, ',').each do |entry|
          segments = split_quoted(entry, ';')
          name, sep, value = segments.shift.partition('=')
          name = name.strip.downcase
          next if name.empty? || !name.match?(TOKEN_PATTERN)
          next if preferences.key?(name) # first occurrence wins

          value = sep.empty? ? true : unquote(value.strip)

          params = {}
          segments.each do |segment|
            pname, psep, pvalue = segment.partition('=')
            pname = pname.strip.downcase
            next if pname.empty? || !pname.match?(TOKEN_PATTERN)
            next if params.key?(pname) # first occurrence wins

            params[pname] = psep.empty? ? true : unquote(pvalue.strip)
          end

          preferences[name] = [value, params]
          order << name
        end
      end

      new(preferences, order)
    end

    def initialize(preferences = {}, order = preferences.keys)
      @preferences = preferences
      @order = order
      @applied = []
    end

    # Whether the preference was requested.
    def key?(name)
      @preferences.key?(name.to_s.downcase)
    end
    alias include? key?

    # The requested value of the preference: a String, +true+ if the
    # preference was given without a value, or nil if the preference
    # was not requested.
    def [](name)
      entry = @preferences[name.to_s.downcase]
      entry && entry[0]
    end

    # The extension parameters of the preference as a Hash, or an
    # empty Hash if the preference was not requested or has no
    # parameters.
    def params(name)
      entry = @preferences[name.to_s.downcase]
      entry ? entry[1].dup : {}
    end

    # Yield each requested preference name and value, in the order the
    # preferences first appeared in the header.
    def each
      return to_enum(:each) unless block_given?

      @order.each { |name| yield name, self[name] }
    end

    # Declare that the application honors the given preference. Only
    # preferences actually present in the request can be applied, and
    # if +value+ is given it must match the requested value
    # (case-insensitively). Returns whether the preference was applied.
    def apply(name, value = nil)
      name = name.to_s.downcase
      entry = @preferences[name]
      return false unless entry

      requested = entry[0]
      unless value.nil?
        return false unless requested.is_a?(String) && requested.casecmp?(value.to_s)
      end

      @applied << name unless @applied.include?(name)
      true
    end

    # Whether the application has applied the given preference.
    def applied?(name)
      @applied.include?(name.to_s.downcase)
    end

    # The names of the applied preferences, in the order they were
    # applied.
    def applied
      @applied.dup
    end

    # The applied preferences serialized for use as a
    # +Preference-Applied+ response header value. Values are the
    # normalized requested values, never the raw client header.
    def applied_header
      @applied.map { |name| self.class.format(name, self[name]) }.join(', ')
    end
  end
end
