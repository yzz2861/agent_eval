# -*- ruby encoding: utf-8 -*-

class Net::LDAP
  class RangedAttribute
    class Description
      attr_reader :name, :options, :range

      def self.parse(description)
        parts = description.to_s.split(';')
        name = parts.shift

        if name.nil? || name.empty?
          raise ArgumentError, "invalid attribute description: #{description.inspect}"
        end

        options = []
        range = nil

        parts.each do |part|
          option_name, separator, value = part.partition('=')
          if separator == '=' && option_name.downcase == 'range'
            range = value
          elsif !part.empty?
            options << part
          end
        end

        new(name, options, range)
      end

      def initialize(name, options, range)
        @name = name
        @options = options
        @range = range
      end

      def request_name(start_index)
        parts = [name]
        parts.concat(options)
        parts << "range=#{start_index}-*"
        parts.join(';')
      end

      def matches?(other)
        name.downcase == other.name.downcase &&
          normalized_options == other.normalized_options
      end

      def parsed_range
        match = /\A(\d+)-(\d+|\*)\z/i.match(range.to_s)
        unless match
          raise Net::LDAP::InvalidRangedAttributeError,
                "invalid ranged attribute marker: #{range.inspect}"
        end

        low = Integer(match[1])
        high = match[2] == '*' ? nil : Integer(match[2])

        if high && high < low
          raise Net::LDAP::InvalidRangedAttributeError,
                "ranged attribute marker moved backwards: #{range}"
        end

        [low, high]
      end

      protected

      def normalized_options
        options.map(&:downcase).sort
      end
    end

    def self.read(ldap, dn, attribute, search_options)
      new(ldap, dn, attribute, search_options).read
    end

    def initialize(ldap, dn, attribute, search_options)
      @ldap = ldap
      @dn = dn
      @attribute = Description.parse(attribute)
      @search_options = search_options.dup
      @version_attribute = @search_options.delete(:version_attribute)
      @version_attribute = @version_attribute.to_s unless @version_attribute.nil?
      @version_description = @version_attribute ? Description.parse(@version_attribute) : nil
      @values = []
      @next_index = 0
    end

    def read
      validate_arguments

      loop do
        entry = read_entry
        version = check_version(entry)
        description, values = returned_attribute(entry)

        if description.nil?
          unless @next_index.zero?
            raise Net::LDAP::InvalidRangedAttributeError,
                  "ranged attribute disappeared before an end marker was received"
          end

          return []
        end

        if description.range.nil?
          unless @next_index.zero?
            raise Net::LDAP::InvalidRangedAttributeError,
                  "received an attribute without a range marker after ranged values had begun"
          end

          return values.dup
        end

        low, high = description.parsed_range
        unless low == @next_index
          raise Net::LDAP::InvalidRangedAttributeError,
                "expected ranged attribute values to start at #{@next_index}, but received #{low}"
        end

        if high && values.length != high - low + 1
          raise Net::LDAP::InvalidRangedAttributeError,
                "ranged attribute returned #{values.length} values for #{description.range}"
        end

        @values.concat(values)

        return @values.dup if high.nil?

        @next_index = high + 1
      end
    end

    private

    def validate_arguments
      if @attribute.range
        raise ArgumentError, "attribute must not include a range marker"
      end

      return unless @version_description

      if @version_description.range
        raise ArgumentError, "version_attribute must not include a range marker"
      end

      if @version_description.matches?(@attribute)
        raise ArgumentError, "version_attribute cannot be the same as the ranged attribute"
      end
    end

    def read_entry
      attributes = [@attribute.request_name(@next_index)]
      attributes << @version_attribute if @version_attribute

      arguments = @search_options.dup
      arguments[:base] = @dn
      arguments[:scope] = Net::LDAP::SearchScope_BaseObject
      arguments[:filter] ||= "objectClass=*"
      arguments[:attributes] = attributes
      arguments[:return_result] = true
      arguments[:ignore_server_caps] = true

      entries = @ldap.search(arguments)

      unless entries
        raise Net::LDAP::RangedAttributeError,
              "unable to read ranged attribute: #{@ldap.get_operation_result.message}"
      end

      entries.first or raise Net::LDAP::RangedAttributeError, "target entry was not returned"
    end

    def check_version(entry)
      return nil unless @version_attribute

      version = entry[@version_attribute]

      if version.empty?
        raise Net::LDAP::RangedAttributeVersionUnavailableError,
              "server did not return version attribute #{@version_attribute.inspect}; " \
              "snapshot consistency cannot be guaranteed"
      end

      @baseline_version ||= version.map(&:dup)

      unless version == @baseline_version
        raise Net::LDAP::RangedAttributeVersionChangedError,
              "version attribute #{@version_attribute.inspect} changed while reading the ranged attribute; " \
              "discarding accumulated results"
      end

      version
    end

    def returned_attribute(entry)
      matches = []

      entry.each_attribute do |name, values|
        next if name == :dn

        description = Description.parse(name)
        matches << [description, values] if description.matches?(@attribute)
      end

      if matches.length > 1
        raise Net::LDAP::InvalidRangedAttributeError,
              "server returned multiple descriptions for attribute #{@attribute.name.inspect}"
      end

      matches.first
    end
  end
end
