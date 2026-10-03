# frozen_string_literal: true

class CSV
  # \CSV::SpreadsheetSafe is an explicit, opt-in write-time strategy that
  # protects generated CSV output against spreadsheet formula injection
  # (also known as CSV injection).
  #
  # CSV files are often opened in spreadsheet applications such as Excel
  # or Google Sheets. Those applications interpret a text cell whose first
  # significant character is =, +, - or @ as a formula, even when
  # the cell is quoted in the CSV output. Leading whitespace and control
  # characters do not prevent this interpretation either. When exported
  # data contains untrusted, user-provided text, such values must be
  # neutralized before writing.
  #
  # The caller declares which fields are numeric (by index or by header
  # name); every other field is treated as untrusted text:
  #
  # * \Numeric objects are always written as-is, so legitimate negative
  #   numbers such as -5 or -3.14 are never modified.
  # * \String values in declared numeric fields are written as-is only
  #   when they are numeric literals; any other string is treated as
  #   untrusted text.
  # * Untrusted text whose first significant character (after skipping
  #   leading whitespace and control characters) is =, +, - or @
  #   gets prefixed with an apostrophe, which forces spreadsheet
  #   applications to render it as text.
  #
  # Each rewritten field is recorded as a
  # \CSV::SpreadsheetSafe::Conversion in #conversions, so callers can
  # audit exactly which fields were transformed.
  #
  # This strategy is only applied when explicitly requested via the
  # :write_converters option; the default behavior of \CSV.generate and
  # friends is unchanged:
  #
  #   headers = ['name', 'balance']
  #   safe = CSV::SpreadsheetSafe.new(numeric_fields: ['balance'],
  #                                   headers: headers)
  #   output = CSV.generate(write_converters: safe.converter) do |csv|
  #     csv << headers
  #     csv << ['=cmd', -5]
  #     csv << ['alice', 3.14]
  #   end
  #   output # => "name,balance\n'=cmd,-5\nalice,3.14\n"
  #   safe.conversions.size # => 1
  class SpreadsheetSafe
    # Records a single field that was rewritten by \CSV::SpreadsheetSafe.
    #
    # * +lineno+ is the 1-based line number of the row being written.
    # * +index+ is the 0-based column index of the field.
    # * +header+ is the header name of the field, or +nil+ when no
    #   headers were declared.
    # * +field+ is the original value.
    # * +sanitized+ is the rewritten value that was written instead.
    Conversion = Struct.new(:lineno, :index, :header, :field, :sanitized,
                            keyword_init: true)

    # The prefix prepended to dangerous untrusted text.
    SANITIZE_PREFIX = "'"

    # Characters that spreadsheet applications interpret as the start of
    # a formula when they appear as the first significant character.
    DANGEROUS_CHARACTERS = ['=', '+', '-', '@'].freeze

    # Matches a string whose first significant character (after leading
    # whitespace and control characters) starts a spreadsheet formula.
    DANGEROUS_PATTERN = /\A[ \p{Cntrl}]*[=+\-@]/

    # Matches a string that is a plain numeric literal, optionally
    # surrounded by whitespace.
    NUMERIC_PATTERN = /\A\s*[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?\s*\z/

    # The field-level records of rewritten fields, in write order:
    # an \Array of \CSV::SpreadsheetSafe::Conversion.
    attr_reader :conversions

    # Creates a new spreadsheet-safe export strategy.
    #
    # +numeric_fields+ declares the fields that hold numbers, as an
    # \Array of 0-based column indices and/or header names (\String or
    # \Symbol). Header names require +headers+, the \Array of header
    # names in column order. All fields not declared as numeric are
    # treated as untrusted text.
    def initialize(numeric_fields: [], headers: nil)
      @headers = headers
      @numeric_indexes = {}
      Array(numeric_fields).each do |name_or_index|
        case name_or_index
        when Integer
          @numeric_indexes[name_or_index] = true
        when String, Symbol
          if @headers.nil?
            message = ':headers is required when you use a field name ' +
                      'in :numeric_fields: ' + name_or_index.inspect
            raise ArgumentError, message
          end
          index = @headers.index(name_or_index.to_s)
          if index.nil?
            message = 'unknown field name in :numeric_fields: ' +
                      name_or_index.inspect
            raise ArgumentError, message
          end
          @numeric_indexes[index] = true
        else
          message = ':numeric_fields element must be ' +
                    'a field index or a field name: ' +
                    name_or_index.inspect
          raise ArgumentError, message
        end
      end
      @conversions = []
    end

    # Returns a write converter suitable for the :write_converters
    # option of \CSV.generate, \CSV.generate_line, CSV#<< and friends.
    def converter
      lambda do |field, field_info|
        sanitize(field, field_info)
      end
    end

    # Whether any field has been rewritten so far.
    def converted?
      not @conversions.empty?
    end

    private
    def sanitize(field, field_info)
      return field unless field.is_a?(String)
      if numeric_field?(field_info) and NUMERIC_PATTERN.match?(field)
        return field
      end
      return field unless dangerous?(field)

      sanitized = SANITIZE_PREFIX + field
      @conversions << Conversion.new(lineno: field_info&.line,
                                     index: field_info&.index,
                                     header: header(field_info),
                                     field: field,
                                     sanitized: sanitized)
      sanitized
    end

    def numeric_field?(field_info)
      return false if field_info.nil? or field_info.index.nil?

      @numeric_indexes.key?(field_info.index)
    end

    def header(field_info)
      return nil if @headers.nil? or field_info.nil? or field_info.index.nil?

      @headers[field_info.index]
    end

    def dangerous?(field)
      if field.valid_encoding?
        DANGEROUS_PATTERN.match?(field)
      else
        DANGEROUS_PATTERN.match?(field.b)
      end
    end
  end
end
