# encoding: utf-8
# frozen_string_literal: true
module Mail
  # Display-oriented body part selection.
  #
  # Mail::DisplayBody walks a message's MIME structure looking for the best
  # body part to display, given the MIME types the caller can display in
  # order of preference:
  #
  #   result = Mail::DisplayBody.select(mail, %w[text/html text/plain])
  #   if result.found?
  #     result.part       # => the Mail::Part (or message) to display
  #     result.resources  # => CID parts (inline images etc.) belonging to
  #                       #    the same multipart/related branch
  #   end
  #
  # Selection follows the MIME structure instead of scanning every part:
  #
  # * multipart/alternative - the caller's type order decides; branches are
  #   tried in document order within each type.
  # * multipart/related - the root part is the one referenced by the
  #   +start+ parameter, or the first part that is not an attachment.
  #   Sibling parts carrying a Content-ID are collected as the result's
  #   resources; resources from other branches are never mixed in.
  # * other multiparts (mixed, report, ...) - the first displayable part in
  #   document order wins.
  # * message/rfc822 - not descended into unless +search_nested: true+.
  #
  # Parts with an explicit Content-Disposition: attachment are never
  # selected. When nothing displayable is found the result is empty:
  # +part+ is nil and +resources+ is empty.
  class DisplayBody
    # The selected part to display, or nil when nothing was displayable.
    attr_reader :part

    # Parts with a Content-ID that belong to the selected part's
    # multipart/related branch, innermost group first. Empty when no part
    # was selected.
    attr_reader :resources

    def initialize(part = nil, resources = [])
      @part = part
      @resources = resources
    end

    # True when a displayable part was found.
    def found?
      !part.nil?
    end

    # True when no displayable part was found.
    def empty?
      part.nil?
    end

    # Selects the best displayable body part of +message+. +mime_types+
    # lists the MIME types the caller can display, most preferred first.
    def self.select(message, mime_types, search_nested: false)
      Selector.new(mime_types, search_nested).select(message) || new
    end

    # Walks the MIME tree; see Mail::DisplayBody for the selection rules.
    class Selector # :nodoc:
      def initialize(mime_types, search_nested)
        @mime_types = Array(mime_types).map { |type| type.to_s.downcase }
        @search_nested = search_nested
      end

      def select(node, types = @mime_types)
        return nil if types.empty? || explicit_attachment?(node)

        if node.multipart?
          select_from_multipart(node, types)
        elsif rfc822?(node)
          select_from_rfc822(node, types)
        elsif types.include?(leaf_mime_type(node))
          DisplayBody.new(node)
        end
      end

      private

      def select_from_multipart(node, types)
        case node.sub_type.to_s.downcase
        when 'alternative'
          select_from_alternative(node, types)
        when 'related'
          select_from_related(node, types)
        else
          select_first_displayable(node, types)
        end
      end

      def select_from_alternative(node, types)
        types.each do |type|
          node.parts.each do |part|
            result = select(part, [type])
            return result if result
          end
        end
        nil
      end

      def select_from_related(node, types)
        root = related_root(node)
        return nil unless root

        result = select(root, types)
        return nil unless result

        result.resources.concat(related_resources(node, root))
        result
      end

      def select_first_displayable(node, types)
        node.parts.each do |part|
          result = select(part, types)
          return result if result
        end
        nil
      end

      def select_from_rfc822(node, types)
        return nil unless @search_nested

        select(Mail.new(node.body.decoded), types)
      rescue StandardError
        nil
      end

      # The root of a multipart/related group is the part referenced by the
      # +start+ parameter, or the first part that is not an attachment.
      def related_root(node)
        if start = related_start(node)
          root = node.parts.detect { |part| content_id_of(part) == start }
          return root if root
        end
        node.parts.detect { |part| !explicit_attachment?(part) }
      end

      def related_start(node)
        params = node.content_type_parameters
        start = params && params['start']
        start && Utilities.unbracket(start.strip)
      end

      # CID resources are the root's siblings in the related group that
      # carry a Content-ID and are not attachments.
      def related_resources(node, root)
        node.parts.select do |part|
          !part.equal?(root) && has_content_id?(part) && !explicit_attachment?(part)
        end
      end

      def leaf_mime_type(node)
        # Per RFC 2045 a part without a Content-Type defaults to text/plain.
        node.mime_type ? node.mime_type.downcase : 'text/plain'
      end

      def rfc822?(node)
        node.main_type.to_s.downcase == 'message' &&
          node.sub_type.to_s.downcase == 'rfc822'
      end

      def explicit_attachment?(node)
        disposition = node.header[:content_disposition]
        disposition.respond_to?(:disposition_type) &&
          disposition.disposition_type.to_s.downcase == 'attachment'
      end

      def has_content_id?(part)
        part.respond_to?(:has_content_id?) ? part.has_content_id? : !part.content_id.nil?
      end

      def content_id_of(part)
        Utilities.unbracket(part.content_id.to_s.strip) if has_content_id?(part)
      end
    end
  end
end
