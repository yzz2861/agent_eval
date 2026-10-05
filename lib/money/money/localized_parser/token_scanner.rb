# frozen_string_literal: true

class Money
  class LocalizedParser
    module TokenScanner
      def tokenize(value)
        text = value.dup
        opening = remove_outer_parentheses!(text)
        prefix_marker, suffix_marker, sign = scan_ends(text)
        inner_opening = !!text.sub!(/\A#{RegionRules::SPACES}*[（(]#{RegionRules::SPACES}*/, "")
        inner_closing = !!text.sub!(/#{RegionRules::SPACES}*[)）]#{RegionRules::SPACES}*\z/, "")
        number = text
        parenthesized = opening || (inner_opening && inner_closing)
        raise InvalidAmount, "unbalanced parentheses" if inner_opening != inner_closing
        raise InvalidAmount, "parentheses can only denote a negative amount" if parenthesized && sign
        raise InvalidAmount, "invalid localized amount" unless number.match?(/\d/)

        {
          parenthesized: parenthesized,
          prefix_marker: prefix_marker,
          suffix_marker: suffix_marker,
          sign: sign,
          number: number,
        }
      end

      private
      def remove_outer_parentheses!(text)
        return false unless text.match?(/\A#{RegionRules::SPACES}*[（(].*[)）]#{RegionRules::SPACES}*\z/m)

        text.sub!(/\A#{RegionRules::SPACES}*[（(]#{RegionRules::SPACES}*/, "")
        text.sub!(/#{RegionRules::SPACES}*[)）]#{RegionRules::SPACES}*\z/, "")
        true
      end

      def scan_ends(text)
        markers = []
        signs = []
        trim_spaces(text)
        2.times do
          sign_value = consume_leading_sign(text)
          if sign_value
            raise InvalidAmount, "multiple signs" unless signs.compact.empty?
            signs << sign_value
          end
          marker = consume_leading_marker(text)
          markers << [:prefix, marker] if marker
          trim_spaces(text)
        end
        2.times do
          trim_spaces(text)
          sign_value = consume_trailing_sign(text)
          if sign_value
            raise InvalidAmount, "multiple signs" unless signs.compact.empty?
            signs << sign_value
          end
          trim_spaces(text)
          marker = consume_trailing_marker(text)
          markers << [:suffix, marker] if marker
        end
        trim_spaces(text)
        signs.compact!
        raise InvalidAmount, "multiple signs" if signs.length > 1
        raise InvalidAmount, "multiple currency markers" if markers.length > 1

        prefix = markers.find { |position, _| position == :prefix }&.last
        suffix = markers.find { |position, _| position == :suffix }&.last
        [prefix, suffix, signs.first]
      end

      def trim_spaces(text)
        text.sub!(/\A#{RegionRules::SPACES}+/, "")
        text.sub!(/#{RegionRules::SPACES}+\z/, "")
      end

      def consume_leading_sign(text)
        match = text.match(/\A(?<sign>[+-])#{RegionRules::SPACES}*/)
        return nil unless match

        text[match.begin(0)...match.end(0)] = ""
        match[:sign]
      end

      def consume_trailing_sign(text)
        match = text.match(/#{RegionRules::SPACES}*(?<sign>[+-])\z/)
        return nil unless match

        text[match.begin(0)...match.end(0)] = ""
        match[:sign]
      end

      def consume_leading_marker(text)
        marker = find_marker(text, leading: true)
        remove_marker(text, marker, leading: true)
        marker
      end

      def consume_trailing_marker(text)
        marker = find_marker(text, leading: false)
        remove_marker(text, marker, leading: false)
        marker
      end

      def find_marker(text, leading:)
        marker_keys.sort_by { |item| exact_match_priority(text, item, leading) }
                   .find { |item| matches_marker?(text, item, leading, true) } ||
          marker_keys.find { |item| matches_marker?(text, item, leading, false) }
      end

      def exact_match_priority(text, marker, leading)
        position = leading ? 0 : text.length - marker.length
        text[position, marker.length] == marker ? -marker.length : 0
      end

      def matches_marker?(text, marker, leading, case_sensitive)
        if !case_sensitive && marker.length == 1 && !currency_index.fetch(marker).include?(@locale.fetch(:currency))
          return false
        end

        if leading
          position_match = text.start_with?(marker)
          position_match ||= text.match?(/\A#{Regexp.escape(marker)}/i) unless case_sensitive
        else
          position_match = text.end_with?(marker)
          position_match ||= text.match?(/#{Regexp.escape(marker)}\z/i) unless case_sensitive
        end
        position_match
      end

      def remove_marker(text, marker, leading:)
        return unless marker

        if leading
          text[0, marker.length] = ""
        else
          text[-marker.length..] = ""
        end
      end
    end
  end
end
