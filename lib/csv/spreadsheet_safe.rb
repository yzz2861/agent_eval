# frozen_string_literal: true

class CSV
  # CSV::SpreadsheetSafe provides an explicit, opt-in export strategy
  # that protects generated CSV output from formula injection when the
  # file is opened in spreadsheet applications (Excel, LibreOffice,
  # Google Sheets, ...).
  #
  # A spreadsheet application may interpret a cell whose text starts
  # with <tt>=</tt>, <tt>+</tt>, <tt>-</tt> or <tt>@</tt> as a formula,
  # even when the field was quoted in the CSV output.  Leading
  # whitespace and control characters do not prevent this either:
  # some applications ignore them before deciding whether a cell is a
  # formula.  Untrusted text fields therefore need to be escaped
  # *before* they are handed to the CSV writer.
  #
  # This module is deliberately explicit: the caller declares which
  # fields hold numeric values (Numeric objects are always safe,
  # including legitimate negative numbers) and which fields hold
  # untrusted text.  Untrusted text that looks like a formula is
  # escaped by prepending an apostrophe (<tt>'</tt>), which spreadsheet
  # applications render as a literal text marker.
  #
  # Every escaped field is recorded as a
  # CSV::SpreadsheetSafe::Record so callers can audit exactly what was
  # transformed.
  #
  # The default behavior of CSV.generate, CSV.generate_line and
  # CSV#<< is *not* changed by this module; protection only applies
  # when you explicitly export through CSV::SpreadsheetSafe.
  #
  # === Example
  #
  #   exporter = CSV::SpreadsheetSafe::Exporter.new(
  #     numeric_fields: ["balance"],
  #   )
  #   csv_string = exporter.generate(
  #     [
  #       ["alice", 100, "ordinary text"],
  #       ["mallory", -20, "=cmd|'/c calc'!A1"],
  #     ],
  #     headers: ["name", "balance", "note"],
  #   )
  #   # => "name,balance,note\nalice,100,ordinary text\nmallory,-20,'=cmd|'/c calc'!A1\n"
  #   exporter.records
  #   # => [#<struct CSV::SpreadsheetSafe::Record
  #   #      row=2, field="note", field_index=2,
  #   #      original="=cmd|'/c calc'!A1", sanitized="'=cmd|'/c calc'!A1">]
  #
  module SpreadsheetSafe
    # Characters that make a spreadsheet application interpret a cell
    # as a formula when they appear as the first significant character.
    DANGEROUS_PREFIXES = ["=", "+", "-", "@"].freeze

    # The default escape marker prepended to dangerous text fields.
    DEFAULT_ESCAPE_PREFIX = "'"

    # Leading characters that spreadsheet applications may skip before
    # deciding whether a cell contains a formula: whitespace *and*
    # control characters.  Detection must look past all of them; only
    # checking the first character (or the first visible character) of
    # a field is not sufficient.
    IGNORED_LEADING_PATTERN = /\A(?:[[:space:]]|[[:cntrl:]])+/

    # A field-level record describing a single transformation applied
    # during export.
    #
    # * +row+: the 1-based line number of the row in the generated
    #   output (the header row, when written, is line 1).
    # * +field+: the field name (when headers are used) or the field
    #   index.
    # * +field_index+: the 0-based column index of the field.
    # * +original+: the field value before escaping.
    # * +sanitized+: the field value written to the output.
    Record = Struct.new(:row, :field, :field_index, :original, :sanitized,
                        keyword_init: true)

    # Returns whether +value+ is a String that a spreadsheet
    # application could interpret as a formula.
    #
    # Leading whitespace and control characters are ignored for the
    # check, because some applications strip them before evaluating a
    # cell.  Non-String values (including all Numeric objects, so
    # legitimate negative numbers) are never dangerous.
    def self.dangerous?(value)
      return false unless value.is_a?(String)
      return false if value.empty?
      return true unless value.valid_encoding?

      candidate = value.sub(IGNORED_LEADING_PATTERN, "")
      return false if candidate.empty?

      DANGEROUS_PREFIXES.include?(candidate[0])
    end

    # Returns +value+ escaped for safe spreadsheet export when it is
    # dangerous text; returns +value+ unchanged otherwise.
    def self.sanitize(value, prefix: DEFAULT_ESCAPE_PREFIX)
      return value unless dangerous?(value)

      prefix + value
    end

    # Explicit, policy-driven CSV exporter.
    #
    # The caller declares which fields are numeric and which are
    # untrusted text:
    #
    # * +numeric_fields+: an Array of field references (0-based Integer
    #   indexes, or header names as Strings/Symbols).  Numeric values
    #   in these fields are written as-is, including legitimate
    #   negative numbers.  String values in these fields are still
    #   treated as untrusted text and escaped when dangerous.
    # * +text_fields+: an Array of field references to treat as
    #   untrusted text.  When omitted (or +nil+), *every* field that is
    #   not declared numeric is treated as untrusted text (safe
    #   default).
    # * +prefix+: the escape marker prepended to dangerous text
    #   (default: <tt>"'"</tt>).
    # * +undeclared+: how to handle fields that appear in neither
    #   +numeric_fields+ nor an explicitly given +text_fields+ list:
    #   <tt>:sanitize</tt> (default, treat as untrusted text),
    #   <tt>:pass</tt> (write as-is) or <tt>:raise</tt> (raise
    #   ArgumentError).  This option has no effect when +text_fields+
    #   is +nil+, because every non-numeric field is then untrusted
    #   text by definition.
    class Exporter
      # The field-level records of the transformations applied by the
      # most recent exports: an Array of CSV::SpreadsheetSafe::Record.
      attr_reader :records

      def initialize(numeric_fields: [],
                     text_fields: nil,
                     prefix: DEFAULT_ESCAPE_PREFIX,
                     undeclared: :sanitize)
        unless [:sanitize, :pass, :raise].include?(undeclared)
          raise ArgumentError,
                ":undeclared must be :sanitize, :pass or :raise: " +                "#{undeclared.inspect}"
        end
        @numeric_fields = numeric_fields
        @text_fields = text_fields
        @prefix = prefix
        @undeclared = undeclared
        @records = []
      end

      # Generates a CSV String from +rows+ (an Array of Arrays,
      # CSV::Row objects or, when +headers+ is given, Hashes), escaping
      # dangerous untrusted text fields.
      #
      # +headers+, when given, are written as the first row and are
      # used to resolve field names in +numeric_fields+ and
      # +text_fields+.  Headers themselves are treated as untrusted
      # text and escaped when dangerous.
      #
      # Additional keyword +options+ (such as +:col_sep+ or
      # +:force_quotes+) are passed through to CSV.generate; quoting
      # behavior is unchanged, and quoting alone is never considered
      # sufficient protection.
      #
      # Returns the generated CSV String.  Field-level records of the
      # applied transformations are available via #records.
      def generate(rows, headers: nil, **options)
        @records = []
        headers = headers.map {|header| header.to_s} if headers
        numeric_indexes = resolve_field_indexes(@numeric_fields, headers)
        text_indexes = @text_fields &&
                       resolve_field_indexes(@text_fields, headers)

        line_number = 0
        CSV.generate(**options) do |csv|
          if headers
            line_number += 1
            csv << sanitize_row(headers, line_number,
                                numeric_indexes, text_indexes, headers)
          end
          rows.each do |row|
            line_number += 1
            row = normalize_row(row, headers)
            csv << sanitize_row(row, line_number,
                                numeric_indexes, text_indexes, headers)
          end
        end
      end

      private

      def resolve_field_indexes(field_references, headers)
        field_references.map do |reference|
          case reference
          when Integer
            reference
          when String, Symbol
            if headers.nil?
              raise ArgumentError,
                    ":headers is required when you use a field name: " +                    "#{reference.inspect}"
            end
            index = headers.index(reference.to_s)
            if index.nil?
              raise ArgumentError,
                    "unknown field name: #{reference.inspect}: " +                    "headers: #{headers.inspect}"
            end
            index
          else
            raise ArgumentError,
                  "field reference must be an index or a field name: " +                  "#{reference.inspect}"
          end
        end
      end

      def normalize_row(row, headers)
        case row
        when CSV::Row
          row.fields
        when Hash
          if headers.nil?
            raise ArgumentError,
                  ":headers is required when you export Hash rows"
          end
          headers.collect {|header| row[header]}
        else
          row
        end
      end

      def sanitize_row(row, line_number, numeric_indexes, text_indexes,
                       headers)
        row.each_with_index.collect do |field, index|
          sanitize_field(field, index, line_number,
                         numeric_indexes, text_indexes, headers)
        end
      end

      def sanitize_field(field, index, line_number,
                         numeric_indexes, text_indexes, headers)
        return field if field.is_a?(Numeric)

        policy = field_policy(index, numeric_indexes, text_indexes)
        case policy
        when :pass
          field
        when :raise
          raise ArgumentError,
                "undeclared field at index #{index}: " +                "declare it in :numeric_fields or :text_fields"
        else
          sanitized = SpreadsheetSafe.sanitize(field, prefix: @prefix)
          if !sanitized.equal?(field)
            @records << Record.new(
              row: line_number,
              field: headers ? headers[index] : index,
              field_index: index,
              original: field,
              sanitized: sanitized,
            )
          end
          sanitized
        end
      end

      def field_policy(index, numeric_indexes, text_indexes)
        return :sanitize if numeric_indexes.include?(index)
        return :sanitize if text_indexes.nil?
        return :sanitize if text_indexes.include?(index)

        @undeclared
      end
    end

    # Convenience one-shot export: generates a CSV String from +rows+
    # using an Exporter built from the given policy.
    #
    # Returns a 2-element Array of the generated CSV String and the
    # field-level records of the applied transformations.
    #
    #   csv_string, records = CSV::SpreadsheetSafe.generate(
    #     [["name", "note"], ["mallory", "=1+1"]],
    #     numeric_fields: [],
    #   )
    #   csv_string # => "name,note\nmallory,'=1+1\n"
    def self.generate(rows,
                      headers: nil,
                      numeric_fields: [],
                      text_fields: nil,
                      prefix: DEFAULT_ESCAPE_PREFIX,
                      undeclared: :sanitize,
                      **options)
      exporter = Exporter.new(numeric_fields: numeric_fields,
                              text_fields: text_fields,
                              prefix: prefix,
                              undeclared: undeclared)
      [exporter.generate(rows, headers: headers, **options),
       exporter.records]
    end
  end
end
