# frozen_string_literal: true

require "strscan"

module Liquid
  class SourceMap
    # Byte-oriented scan of a template into text, tag and variable regions.
    #
    # Unlike Liquid::Tokenizer this scanner never hands sliced copies of the
    # source to the parser. Every emitted region carries its absolute byte
    # offsets within the original source, so unmodified regions can be emitted
    # back verbatim (CRLF, whitespace-control hyphens, irregular indentation
    # and all).
    class RegionScanner
      TEXT     = :text
      TAG      = :tag
      VARIABLE = :variable

      Region = Struct.new(
        :kind, :start_byte, :end_byte,
        :tag_name, :markup_start_byte, :markup_end_byte, :opaque,
        keyword_init: true,
      ) do
        def slice(source)
          source.byteslice(start_byte, end_byte - start_byte)
        end

        def markup(source)
          return unless markup_start_byte && markup_end_byte
          source.byteslice(markup_start_byte, markup_end_byte - markup_start_byte)
        end
      end

      OPEN_BRACE  = "{".ord
      CLOSE_BRACE = "}".ord
      PERCENT     = "%".ord

      TAG_TOKEN = /
        \A\{%
        (?<open_wc>-)?
        \s*
        (?<name>#{TagName})
        \s*
        (?<rest>.*?)
        (?<close_wc>-)?
        %\}\z
      /xom
      INVALID_TAG_TOKEN = /\A\{%(?:-)?\s*(?<name>\w+).*?(?:-)?%\}\z/om
      VARIABLE_TOKEN = /\A\{\{(?:-)?(?<markup>.*?)(?:-)?\}\}\z/om

      def self.scan(source)
        new(source).scan
      end

      def initialize(source)
        @source = source
        @ss = StringScanner.new(source.b)
      end

      def scan
        @regions = []

        until @ss.eos?
          start = @ss.pos
          byte = @ss.get_byte

          if byte == "{"
            peek = @ss.peek_byte
            if peek == PERCENT
              @ss.get_byte
              scan_tag(start)
              next
            elsif peek == OPEN_BRACE
              @ss.get_byte
              scan_variable(start)
              next
            end
          end

          scan_text(start)
        end

        @regions
      end

      private

      def scan_text(start)
        unless @ss.skip_until(/\{[{%]/)
          @ss.terminate
        end
        finish = @ss.pos
        unless @ss.eos?
          finish -= 2
          @ss.pos = finish
        end
        return if finish == start

        @regions << Region.new(kind: TEXT, start_byte: start, end_byte: finish)
      end

      def scan_variable(start)
        loop do
          byte = @ss.get_byte&.ord
          if byte.nil?
            emit_text_tail(start)
            return
          end

          if byte == CLOSE_BRACE && @ss.peek_byte == CLOSE_BRACE
            @ss.get_byte
            emit_variable(start, @ss.pos)
            return
          end
        end
      end

      def emit_variable(start, finish)
        token = @source.byteslice(start, finish - start)
        region = Region.new(kind: VARIABLE, start_byte: start, end_byte: finish)
        if (match = VARIABLE_TOKEN.match(token))
          region.markup_start_byte = start + match.begin(:markup)
          region.markup_end_byte   = start + match.end(:markup)
        end
        @regions << region
      end

      def scan_tag(start)
        unless @ss.skip_until(/%\}/)
          emit_text_tail(start)
          return
        end

        finish = @ss.pos
        token = @source.byteslice(start, finish - start)
        match = TAG_TOKEN.match(token) || INVALID_TAG_TOKEN.match(token)

        unless match
          @regions << Region.new(kind: TEXT, start_byte: start, end_byte: finish)
          return
        end

        region = Region.new(
          kind: TAG,
          start_byte: start,
          end_byte: finish,
          tag_name: match[:name],
        )
        if match.names.include?('rest')
          region.markup_start_byte = start + match.begin(:rest)
          region.markup_end_byte   = start + match.end(:rest)
        end

        @regions << region
        scan_opaque_body(region)
      end

      # Raw, comment and doc bodies are not live liquid: their contents are
      # swallowed into a single verbatim TEXT region delimited by the open and
      # close tag regions. Inline comments are a single opaque tag region.
      def scan_opaque_body(open_region)
        name = open_region.tag_name

        case name
        when '#'
          open_region.opaque = true
        when 'raw', 'doc'
          swallow_body(open_region, "end#{name}")
        when 'comment'
          swallow_comment_body(open_region)
        end
      end

      def swallow_body(open_region, closing_name)
        body_start = open_region.end_byte

        until @ss.eos?
          unless @ss.skip_until(/\{%/)
            @ss.terminate
            break
          end
          found = scan_to_tag_end
          unless found
            @ss.terminate
            break
          end
          tag_start, tag_finish, match = found

          if match[:name] == closing_name
            emit_opaque_text(body_start, tag_start)
            @regions << build_tag_region(tag_start, tag_finish, match)
            return
          end
        end

        # Unclosed block: remainder is verbatim text.
        emit_opaque_text(body_start, @ss.pos)
      end

      def swallow_comment_body(open_region)
        body_start = open_region.end_byte
        depth = 1
        in_raw = false

        until @ss.eos?
          unless @ss.skip_until(/\{%/)
            @ss.terminate
            break
          end
          found = scan_to_tag_end
          unless found
            @ss.terminate
            break
          end
          tag_start, tag_finish, match = found
          tag_name = match[:name]
          if in_raw
            in_raw = false if tag_name == 'endraw'
            next
          end

          case tag_name
          when 'raw'
            in_raw = true
          when 'comment'
            depth += 1
          when 'endcomment'
            depth -= 1
            if depth.zero?
              emit_opaque_text(body_start, tag_start)
              @regions << build_tag_region(tag_start, tag_finish, match)
              return
            end
          end
        end

        emit_opaque_text(body_start, @ss.pos)
      end

      def emit_opaque_text(start_byte, end_byte)
        return if end_byte <= start_byte
        @regions << Region.new(kind: TEXT, start_byte: start_byte, end_byte: end_byte, opaque: true)
      end

      # After skip_until(/\{%/), consumes through the closing %}/ and returns
      # [tag_start_byte, tag_finish_byte, match_data] or nil.
      def scan_to_tag_end
        tag_start = @ss.pos - 2
        return nil unless @ss.skip_until(/%\}/)

        tag_finish = @ss.pos
        token = @source.byteslice(tag_start, tag_finish - tag_start)
        match = TAG_TOKEN.match(token) || INVALID_TAG_TOKEN.match(token)
        return nil unless match

        [tag_start, tag_finish, match]
      end

      def build_tag_region(tag_start, tag_finish, match)
        region = Region.new(
          kind: TAG,
          start_byte: tag_start,
          end_byte: tag_finish,
          tag_name: match[:name],
        )
        if match.names.include?('rest')
          region.markup_start_byte = tag_start + match.begin(:rest)
          region.markup_end_byte   = tag_start + match.end(:rest)
        end
        region
      end

      def emit_text_tail(start)
        @ss.terminate
        finish = @ss.pos
        return if finish == start

        @regions << Region.new(kind: TEXT, start_byte: start, end_byte: finish)
      end
    end
  end
end
