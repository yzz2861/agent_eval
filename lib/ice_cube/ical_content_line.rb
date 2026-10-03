module IceCube
  class IcalContentLine
    Parameter = Struct.new(:name, :value, :quoted, :raw_value, keyword_init: true) do
      def to_s
        rendered_name = name.to_s.upcase
        if quoted
          %(#{rendered_name}="#{raw_value || value}")
        else
          "#{rendered_name}=#{value}"
        end
      end
    end

    Component = Struct.new(:name, :value, keyword_init: true) do
      def to_s
        "#{name.to_s.upcase}=#{value}"
      end
    end

    attr_reader :name, :params, :value, :line_number, :column, :byte_offset

    def initialize(name:, params:, value:, line_number:, column:, byte_offset:)
      @name = name
      @params = params
      @value = value
      @line_number = line_number
      @column = column
      @byte_offset = byte_offset
    end

    def to_s
      rendered_params = params.map { |param| ";#{param}" }.join
      "#{name.upcase}#{rendered_params}:#{value}"
    end

  end
end
