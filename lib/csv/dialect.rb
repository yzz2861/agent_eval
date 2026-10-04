# frozen_string_literal: true

require "stringio"

class CSV
  # Result of CSV.detect_dialect.
  Dialect = Struct.new(:status,
                       :col_seps,
                       :quote_chars,
                       :row_seps,
                       :prefix,
                       :read_limit,
                       :notes) do
    def detected?
      status == :detected
    end

    def ambiguous?
      status == :ambiguous
    end

    def insufficient_data?
      status == :insufficient_data
    end

    def malformed?
      status == :malformed
    end

    def to_options
      {
        col_sep: col_seps.first || ",",
        row_sep: row_seps.first || :auto,
        quote_char: quote_chars.first || '"',
      }
    end

    def replay_io
      DialectDetector::PrefixedIO.new(prefix, @input)
    end

    def csv(**options, &block)
      csv = CSV.new(replay_io, **to_options.merge(options))
      if block
        begin
          yield csv
        ensure
          csv.close
        end
      else
        csv
      end
    end

    def to_h
      super.merge(col_seps: col_seps.dup,
                  quote_chars: quote_chars.dup,
                  row_seps: row_seps.dup,
                  notes: notes.dup)
    end

    private

    def initialize_copy(other)
      super
      self.col_seps = other.col_seps.dup
      self.quote_chars = other.quote_chars.dup
      self.row_seps = other.row_seps.dup
      self.notes = other.notes.dup
    end
  end

  # Detects CSV dialect from a bounded prefix while preserving that prefix
  # for a later parser.
  class DialectDetector
    # IO wrapper that replays data consumed by detection before delegating to
    # the original, non-rewindable IO.
    class PrefixedIO
      def initialize(prefix, io)
        @prefix = StringIO.new(prefix)
        @io = io
      end

      def gets(*args)
        unless @prefix.eof?
          chunk = @prefix.gets(*args)
          return chunk if chunk
        end
        @io.gets(*args)
      end

      def read(length = nil, outbuf = nil)
        data = +""
        if length.nil?
          data << @prefix.read unless @prefix.eof?
          data << @io.read if @io.respond_to?(:read)
        else
          remaining = length
          unless @prefix.eof?
            chunk = @prefix.read(remaining)
            data << chunk if chunk
            remaining -= data.bytesize
          end
          if remaining > 0 && @io.respond_to?(:read)
            data << @io.read(remaining)
          end
        end
        if outbuf
          outbuf.replace(data)
          outbuf
        else
          data
        end
      end

      def eof?
        return false unless @prefix.eof?
        @io.eof?
      end

      def close
      end

      def external_encoding
        @io.external_encoding if @io.respond_to?(:external_encoding)
      end

      def internal_encoding
        @io.internal_encoding if @io.respond_to?(:internal_encoding)
      end

      def encoding
        @io.encoding if @io.respond_to?(:encoding)
      end
    end

    DEFAULT_COLUMN_SEPARATORS = [",", ";", "\t"].freeze
    DEFAULT_QUOTE_CHARACTERS = ['"', "'"].freeze

    Analysis = Struct.new(:quote_char,
                          :errors,
                          :counts,
                          :row_separators,
                          :completed_records,
                          :quote_observed,
                          :quote_used,
                          :incomplete_record,
                          :observed_separators) do
      def valid?
        errors.empty?
      end
    end

    def initialize(input,
                   read_limit,
                   col_seps: DEFAULT_COLUMN_SEPARATORS,
                   quote_chars: DEFAULT_QUOTE_CHARACTERS)
      @input = input
      @read_limit = read_limit
      @col_seps = col_seps.dup
      @quote_chars = quote_chars.dup
      @prefix = +""
      @eof = false
      validate_candidates
    end

    def detect
      read_prefix
      analyses = {}
      @quote_chars.each do |quote_char|
        analyses[quote_char] = analyze(quote_char)
      end
      analyses[nil] = analyze(nil)

      chosen = choose_analyses(analyses)
      build_result(analyses, chosen)
    end

    private

    def validate_candidates
      @col_seps.each do |col_sep|
        unless col_sep.is_a?(String) && col_sep.length == 1
          raise ArgumentError, "col_seps must contain single-character Strings"
        end
      end
      @quote_chars.each do |quote_char|
        unless quote_char.nil? ||
               (quote_char.is_a?(String) && quote_char.length == 1)
          raise ArgumentError, "quote_chars must contain nil or single-character Strings"
        end
      end
      if @col_seps.empty?
        raise ArgumentError, "col_seps must not be empty"
      end
    end

    def read_prefix
      remaining = @read_limit
      until remaining <= 0
        chunk = @input.gets(nil, remaining)
        break if chunk.nil?
        @prefix << chunk
        remaining -= chunk.bytesize
      end
      @eof = !@input.respond_to?(:eof?) || @input.eof?
    rescue IOError
      @eof = @prefix.empty?
    end

    def analyze(quote_char)
      counts = {}
      @col_seps.each { |col_sep| counts[col_sep] = [] }
      current_counts = Hash.new(0)
      row_separators = Hash.new(0)
      errors = []
      completed_records = 0
      quote_observed = false
      quote_used = false
      record_has_data = false
      observed_separators = []
      state = :unquoted
      at_field_start = true
      incomplete_record = false

      index = 0
      while index < @prefix.length
        char = @prefix[index]
        if state == :quoted
          state = :after_quoted if quote_char && char == quote_char
          index += 1
          next
        end

        if char == "\r" && @prefix[index + 1] == "\n"
          if state == :after_quoted
            add_row_separator(row_separators, "\r\n", errors)
            state = :unquoted
          elsif state == :unquoted
            add_row_separator(row_separators, "\r\n", errors)
          end
          finalize_record(counts, current_counts, record_has_data)
          completed_records += 1 if record_has_data
          reset_record(current_counts)
          record_has_data = false
          state = :unquoted
          at_field_start = true
          index += 2
          next
        elsif char == "\r" || char == "\n"
          if state == :after_quoted
            add_row_separator(row_separators, char, errors)
            state = :unquoted
          elsif state == :unquoted
            add_row_separator(row_separators, char, errors)
          end
          finalize_record(counts, current_counts, record_has_data)
          completed_records += 1 if record_has_data
          reset_record(current_counts)
          record_has_data = false
          state = :unquoted
          at_field_start = true
          index += 1
          next
        end

        if quote_char && char == quote_char
          quote_observed = true
          if state == :after_quoted
            state = :quoted
          elsif at_field_start
            quote_used = true
            state = :quoted
            at_field_start = false
            record_has_data = true
          else
            errors << :illegal_quote
          end
        elsif state == :after_quoted && !@col_seps.include?(char)
          errors << :illegal_quote
        elsif @col_seps.include?(char)
          current_counts[char] += 1
          observed_separators << char unless observed_separators.include?(char)
          record_has_data = true
          at_field_start = true
          state = :unquoted if state == :after_quoted
        else
          record_has_data = true
          at_field_start = false
        end
        index += 1
      end

      if state == :quoted
        if @eof
          errors << :unclosed_quote
        else
          incomplete_record = true
        end
      elsif !@eof && (record_has_data || @prefix.end_with?("\r"))
        incomplete_record = true
      elsif record_has_data
        finalize_record(counts, current_counts, true)
        completed_records += 1
      end

      Analysis.new(quote_char,
                   errors,
                   counts,
                   row_separators,
                   completed_records,
                   quote_observed,
                   quote_used,
                   incomplete_record,
                   observed_separators)
    end

    def add_row_separator(row_separators, row_sep, errors)
      row_separators[row_sep] += 1
      if row_separators.size > 1
        errors << :mixed_row_separator unless errors.include?(:mixed_row_separator)
      end
    end

    def finalize_record(counts, current_counts, record_has_data)
      return unless record_has_data
      @col_seps.each { |col_sep| counts[col_sep] << current_counts[col_sep] }
    end

    def reset_record(current_counts)
      current_counts.clear
    end

    def choose_analyses(analyses)
      valid = analyses.values.select(&:valid?)
      used = valid.select(&:quote_used)
      return used unless used.empty?

      if @eof && analyses.values.any? { |analysis| analysis.errors.include?(:unclosed_quote) }
        return []
      end

      conventional = valid.find do |analysis|
        analysis.quote_char == '"' && !analysis.quote_observed
      end
      return [conventional] if conventional

      no_quote = valid.find { |analysis| analysis.quote_char.nil? }
      no_quote ? [no_quote] : []
    end

    def build_result(analyses, chosen)
      if chosen.empty?
        notes = analyses.values.flat_map { |analysis| error_notes(analysis) }.uniq
        return result(:malformed, [], [], [], notes)
      end

      col_seps, col_sep_ambiguous = detect_column_separators(chosen)
      quote_chars = chosen.map(&:quote_char).uniq
      row_seps = chosen.flat_map { |analysis| analysis.row_separators.keys }.uniq
      incomplete = chosen.any?(&:incomplete_record)
      notes = []

      notes.concat(quote_notes(chosen))
      if col_seps.empty?
        notes << "No column separator was observed."
      elsif col_sep_ambiguous
        notes << "Multiple column separators produced consistent field counts."
      end
      notes << "No row separator was observed." if row_seps.empty?
      notes << "The sample ends in the middle of a record." if incomplete

      status =
        if !@eof && incomplete
          :insufficient_data
        elsif !@eof && chosen.first.completed_records < 2
          :insufficient_data
        elsif col_seps.empty? || col_sep_ambiguous ||
              quote_chars.size > 1 || quote_chars.first.nil?
          :ambiguous
        else
          :detected
        end

      result(status, col_seps, quote_chars, row_seps, notes)
    end

    def result(status, col_seps, quote_chars, row_seps, notes)
      dialect = Dialect.new(status,
                            col_seps,
                            quote_chars,
                            row_seps,
                            @prefix,
                            @read_limit,
                            notes)
      dialect.instance_variable_set(:@input, @input)
      dialect
    end

    def detect_column_separators(analyses)
      scored = @col_seps.map do |col_sep|
        scores = analyses.map do |analysis|
          counts = analysis.counts[col_sep]
          next(nil) if counts.empty?
          next(nil) unless analysis.observed_separators.include?(col_sep)
          mean = counts.sum / counts.size.to_f
          variance = counts.sum { |count| (count - mean) ** 2 } / counts.size
          [counts.min.zero? ? 1 : 0, variance, counts.sum, mean]
        end.compact
        next(nil) if scores.empty?
        [col_sep, scores.min]
      end.compact
      return [[], false] if scored.empty?

      best_score = scored.map(&:last).min
      best = scored.select { |_, score| score == best_score }.map(&:first)
      [best, best.size > 1]
    end

    def quote_notes(chosen)
      if chosen.size > 1
        ["Multiple quote characters produced valid records."]
      elsif chosen.first.quote_char.nil?
        ["No valid quoted field was detected; quote characters are treated as ordinary data."]
      elsif !chosen.first.quote_observed
        ["No quote character was observed; assuming the conventional double quote."]
      else
        []
      end
    end

    def error_notes(analysis)
      analysis.errors.map do |error|
        case error
        when :unclosed_quote
          "Unclosed quoted field."
        when :illegal_quote
          "Quote character appears in an illegal position."
        when :mixed_row_separator
          "Multiple row separators were observed."
        else
          error.to_s
        end
      end
    end
  end
end
