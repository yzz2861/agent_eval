# encoding: utf-8
# frozen_string_literal: true
require 'mail/constants'
require 'mail/indifferent_hash'
require 'mail/encodings'
require 'mail/utilities'

module Mail
  # Raised in strict RFC 2231 decoding when one or more parameter problems
  # were detected. The partially decoded result and every diagnostic are
  # available on the exception.
  class ParameterError < StandardError
    attr_reader :result

    def initialize(result)
      @result = result
      super("invalid MIME parameters: #{result.diagnostics.map(&:message).join('; ')}")
    end

    def diagnostics
      result.diagnostics
    end
  end

  # A single problem detected while decoding RFC 2045/RFC 2231 parameters.
  #
  # +code+ is one of:
  #
  #   :duplicate_segment       - the same RFC 2231 section index appears twice
  #   :segment_gap             - section indices do not form 0..n without holes
  #   :invalid_percent_encoding- an extended value contains a bad percent escape
  #   :unsupported_charset     - the declared charset cannot be handled
  #   :parameter_conflict      - both plain (name=v) and extended (name*=v or
  #                              name*0*=v) forms are present for one parameter
  #
  # Location information identifies the header field (when supplied), the
  # parameter name, the zero based position of the offending parameter in the
  # original parameter list, the RFC 2231 section index (when applicable) and
  # the byte offset inside the merged value (for bad percent escapes). The
  # raw, conflicting parameter fragments are always preserved.
  class ParameterDiagnostic
    attr_reader :code, :parameter, :position, :segment, :offset, :charset,
                :raw_segments, :message

    def initialize(code, parameter:, position:, message:, segment: nil,
                   offset: nil, charset: nil, raw_segments: [], field: nil)
      @code = code
      @parameter = parameter
      @field = field
      @position = position
      @segment = segment
      @offset = offset
      @charset = charset
      @raw_segments = raw_segments
      @message = message
      freeze
    end

    def field
      @field
    end

    def to_h
      hash = {
        :code => code,
        :field => field,
        :parameter => parameter,
        :position => position,
        :segment => segment,
        :offset => offset,
        :charset => charset,
        :raw_segments => raw_segments,
        :message => message
      }
      hash.reject { |_k, v| v.nil? }
    end
    alias to_hash to_h
  end

  # Outcome of a strict parameter decode. +parameters+ holds the best effort
  # decoded values (extended notation is always preferred when it conflicts
  # with plain notation) and +diagnostics+ holds every detected problem.
  class ParameterDecodeResult
    attr_reader :parameters, :diagnostics

    def initialize(parameters, diagnostics)
      @parameters = parameters
      @diagnostics = diagnostics
      freeze
    end

    def errors
      diagnostics
    end

    def valid?
      diagnostics.empty?
    end

    def parameters!
      raise Mail::ParameterError, self unless valid?
      parameters
    end
  end

  # Decodes the ordered list of parameter pairs produced by the content type
  # and content disposition parsers, joining RFC 2231 continuation segments
  # and percent/charset decoding the *merged* byte string so that multi-byte
  # characters split across segments survive.
  #
  # The default, lenient behavior matches Mail::ParameterHash#[] exactly: no
  # diagnostics are produced and every quirk is tolerated. Passing
  # <tt>strict: true</tt> adds explicit validation and returns a
  # ParameterDecodeResult with structured diagnostics while still performing
  # the same best effort decode.
  class ParameterDecoder
    # Matches "name", "name*" (single extended value) and "name*N" /
    # "name*N*" (RFC 2231 continuation segments).
    KEY_PATTERN = /\A(?<base>[^*]+?)(?:\*(?<section>\d+))?(?<extended>\*)?\z/

    # Lenient prefix detection, kept byte for byte compatible with the
    # historical ParameterHash#[] implementation.
    LENIENT_PREFIX = /([\w\-]+)?'(\w\w)?'(.*)/m

    # Strict RFC 2231 prefix: charset'language'value (charset and language
    # may each be blank).
    STRICT_PREFIX = /\A([\w\-]*)'([^']*)'(.*)\z/m

    Entry = Struct.new(:position, :key, :value, :base, :section, :extended)
    private_constant :Entry

    class << self
      # Accepts the parser output (an array of single-key hashes such as
      # <tt>[{"name*0*" => "%E4%B8%AD"}]</tt>) or an array of key/value
      # pairs. Returns a decoded IndifferentHash in lenient mode and a
      # ParameterDecodeResult in strict mode.
      def decode(parameter_pairs, strict: false, field: nil)
        entries = build_entries(parameter_pairs)
        groups = group_entries(entries)
        diagnostics = strict ? [] : nil

        parameters = IndifferentHash.new
        groups.each do |base, group|
          diagnostics&.concat(validate_group(base, group, field))
          parameters[base] = decode_group(group)
        end

        strict ? ParameterDecodeResult.new(parameters, diagnostics) : parameters
      end

      # Strict decode that raises Mail::ParameterError when any diagnostic
      # was produced, otherwise returning the decoded IndifferentHash.
      def decode!(parameter_pairs, field: nil)
        decode(parameter_pairs, strict: true, field: field).parameters!
      end

      private

      def build_entries(parameter_pairs)
        entries = []
        Array(parameter_pairs).each_with_index do |pair, position|
          key, value =
            if pair.is_a?(Hash)
              [pair.keys.first.to_s, pair.values.first.to_s]
            else
              [pair[0].to_s, pair[1].to_s]
            end
          entries << build_entry(position, key, value)
        end
        entries
      end

      def build_entry(position, key, value)
        match = KEY_PATTERN.match(key)
        if match && key != match[:base]
          Entry.new(position, key, value, match[:base],
                    match[:section] && match[:section].to_i,
                    !match[:extended].nil?)
        else
          # Plain "name=value" (or an unrecognized key shape, which is
          # treated as a plain parameter).
          Entry.new(position, key, value, key, nil, false)
        end
      end

      def group_entries(entries)
        groups = {}
        entries.each do |entry|
          base = entry.base
          key = groups_key(base)
          group = (groups[key] ||= { :base => base, :plain => [], :sections => {} })
          if entry.section
            (group[:sections][entry.section] ||= []) << entry
          elsif entry.extended
            group[:singleton_extended] ||= entry
          else
            group[:plain] << entry
          end
        end
        groups
      end

      def groups_key(base)
        base.downcase
      end

      # Best effort ordering, kept byte for byte compatible with the
      # historical ParameterHash#[] behavior: the raw keys are sorted
      # lexicographically ("name*10" precedes "name*2").
      def lenient_family_entries(group)
        entries = all_family_entries(group)
        entries.sort_by(&:key)
      end

      # RFC 2231 ordering: continuation segments are joined in numeric
      # section order, starting at zero, with a lone extended value last.
      def strict_family_entries(group)
        entries = []
        group[:sections].keys.sort.each do |section|
          entries.concat(group[:sections][section])
        end
        entries << group[:singleton_extended] if group[:singleton_extended]
        entries
      end

      def all_family_entries(group)
        entries = []
        entries << group[:singleton_extended] if group[:singleton_extended]
        group[:sections].keys.sort.each do |section|
          entries.concat(group[:sections][section])
        end
        entries
      end

      def decode_group(group)
        family = lenient_family_entries(group)
        return last_plain_value(group) if family.empty?

        string = family.map(&:value).join
        if match = string.match(LENIENT_PREFIX)
          string = match[3]
          encoding = match[1]
        end
        Mail::Encodings.param_decode(string, encoding)
      end

      def last_plain_value(group)
        group[:plain].last&.value
      end

      def validate_group(base, group, field)
        diagnostics = []
        plain = group[:plain]
        sections = group[:sections]
        singleton = group[:singleton_extended]
        family = strict_family_entries(group)

        diagnostics.concat(check_conflicts(base, plain, family, field)) if
          plain.any? && family.any?

        if sections.any?
          diagnostics.concat(check_duplicate_sections(base, sections, field))
          diagnostics.concat(check_section_gaps(base, sections, field))
          diagnostics.concat(check_extended_value(base, family, field))
        elsif singleton
          diagnostics.concat(check_extended_value(base, [singleton], field))
        end

        diagnostics
      end

      def check_conflicts(base, plain, family, field)
        fragments = (plain + family).map { |e| fragment(e) }
        location = plain.first.position
        [diagnostic(:parameter_conflict, base, location, field,
                    :raw_segments => fragments,
                    :message => "parameter #{base.inspect} is given in both plain and extended (RFC 2231) forms")]
      end

      def check_duplicate_sections(base, sections, field)
        sections.keys.sort.select { |section| sections[section].length > 1 }.map do |section|
          entries = sections[section]
          diagnostic(:duplicate_segment, base, entries.last.position, field,
                     :segment => section,
                     :raw_segments => entries.map { |e| fragment(e) },
                     :message => "parameter #{base.inspect} repeats RFC 2231 segment #{section} #{entries.length} times")
        end
      end

      def check_section_gaps(base, sections, field)
        present = sections.keys
        entries = present.sort.map { |section| sections[section].first }
        gaps = (0..present.max).to_a - present
        gaps.map do |missing|
          diagnostic(:segment_gap, base, entries.first.position, field,
                     :segment => missing,
                     :raw_segments => entries.map { |e| fragment(e) },
                     :message => "parameter #{base.inspect} is missing RFC 2231 segment #{missing}")
        end
      end

      # Percent escapes and charset conversion are validated on the bytes of
      # the fully merged continuation so a multi-byte character spanning two
      # segments is never broken.
      def check_extended_value(base, family, field)
        diagnostics = []
        # Percent escaping only exists in RFC 2231 extended notation; a
        # literal "%" in a plain parameter value must not be flagged.
        return diagnostics unless family.any?(&:extended)

        first = family.first
        bodies = family.map { |entry| entry.value.dup }
        charset = nil

        if first.extended && (match = STRICT_PREFIX.match(family.map(&:value).join))
          charset = match[1]
          prefix_bytes = (match[0].bytesize - match[3].bytesize)
          bodies[0] = bodies[0].byteslice(prefix_bytes..-1) || ''
        end
        body = bodies.join

        unless charset.nil? || charset.empty? || Mail::Utilities.charset_supported?(charset)
          diagnostics << diagnostic(:unsupported_charset, base, first.position, field,
                                    :segment => first.section,
                                    :charset => charset,
                                    :raw_segments => [fragment(first)],
                                    :message => "parameter #{base.inspect} declares unsupported charset #{charset.inspect}")
        end

        scan_percent_escapes(body, family, bodies).each do |offset, entry|
          diagnostics << diagnostic(:invalid_percent_encoding, base, entry.position, field,
                                    :segment => entry.section,
                                    :offset => offset,
                                    :raw_segments => family.map { |e| fragment(e) },
                                    :message => "parameter #{base.inspect} contains an invalid percent escape at byte #{offset} of the merged value")
        end

        diagnostics
      end

      def scan_percent_escapes(body, family, bodies)
        bad = []
        index = 0
        boundaries = segment_boundaries(family, bodies)
        while (percent = body.index('%', index))
          if body[percent + 1, 2].to_s.length == 2 &&
             body[percent + 1, 2] =~ /\A[0-9A-Fa-f]{2}\z/
            index = percent + 3
          else
            bad << [percent, segment_at(boundaries, percent)]
            index = percent + 1
          end
        end
        bad
      end

      def segment_boundaries(family, bodies)
        offset = 0
        family.each_with_index.map do |entry, index|
          boundary = [offset, entry]
          offset += bodies[index].to_s.bytesize
          boundary
        end
      end

      def segment_at(boundaries, offset)
        current = boundaries.first
        boundaries.each do |boundary_offset, entry|
          break if boundary_offset > offset
          current = [boundary_offset, entry]
        end
        current[1]
      end

      def fragment(entry)
        %(#{entry.key}=#{entry.value})
      end

      def diagnostic(code, parameter, position, field, options)
        ParameterDiagnostic.new(code,
                                :parameter => parameter,
                                :position => position,
                                :field => field,
                                **options)
      end
    end
  end
end
