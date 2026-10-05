# frozen_string_literal: true

module Zip
  class ReproducibleOptions # :nodoc: all
    OPTIONS = {
      sort_entries: true,
      time: true,
      permissions: true,
      fstype: true,
      extra_fields: true
    }.freeze

    attr_reader(*OPTIONS.keys)

    def initialize(options)
      case options
      when true
        enabled = true
        options = OPTIONS.keys.to_h { |name| [name, true] }
      when false
        enabled = false
        options = {}
      when Hash
        enabled = true
      else
        raise ArgumentError, 'Reproducible options must be true, false, or a Hash'
      end

      unknown_options = options.keys - OPTIONS.keys
      unless unknown_options.empty?
        raise ArgumentError, "Unknown reproducible option: #{unknown_options.first.inspect}"
      end

      OPTIONS.each do |name, default|
        value = options.fetch(name, default)
        unless value == true || value == false
          raise ArgumentError, "Reproducible option #{name.inspect} must be true or false"
        end
        instance_variable_set(:"@#{name}", value)
      end

      @enabled = enabled
    end

    def enabled?
      @enabled
    end
  end
end
