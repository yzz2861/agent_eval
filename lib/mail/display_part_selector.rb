# encoding: utf-8
# frozen_string_literal: true

module Mail
  class DisplayPartSelector
    def initialize(message, preferred_types)
      @message = message
      @preferred_types = preferred_types.map { |type| normalize_mime_type(type) }.uniq
    end

    def select
      select_from(@message) || DisplayPartSelection::EMPTY
    end

    private

    def select_from(part)
      return if explicit_attachment?(part)

      if multipart?(part)
        select_multipart(part)
      elsif displayable_leaf?(part) && preferred?(part)
        DisplayPartSelection.new(part, [])
      end
    end

    def select_multipart(part)
      case mime_type(part)
      when 'multipart/alternative'
        select_alternative(part)
      when 'multipart/related'
        select_related(part)
      else
        select_generic(part)
      end
    end

    def select_generic(part)
      part.parts.each do |child|
        next if explicit_attachment?(child)

        selection = select_from(child)
        next unless selection && !selection.empty?

        siblings = part.parts.reject { |sibling| sibling.equal?(child) }
        resources = selection.resources + siblings.flat_map { |sibling| cid_resources(sibling) }
        return DisplayPartSelection.new(selection.part, resources)
      end
      nil
    end

    def select_alternative(part)
      @preferred_types.each do |preferred_type|
        part.parts.each do |child|
          next if explicit_attachment?(child)

          selection = select_from(child)
          next unless selection && !selection.empty?
          return selection if mime_type(selection.part) == preferred_type
        end
      end
      nil
    end

    def select_related(part)
      children = non_attachment_parts(part)
      root = related_root(part, children)
      return unless root

      selection = select_from(root)
      return if selection.nil? || selection.empty?

      resources = selection.resources + related_resources(part, root)
      DisplayPartSelection.new(selection.part, resources)
    end

    def related_root(part, children)
      start = content_type_parameter(part, 'start')

      if start
        root_id = normalize_content_id(start)
        return children.detect do |child|
          normalize_content_id(content_id(child)) == root_id
        end
      end

      children.first
    end

    def related_resources(part, root)
      non_attachment_parts(part).reject { |child| child.equal?(root) }.flat_map do |child|
        cid_resources(child)
      end.uniq
    end

    def cid_resources(part)
      return [] if explicit_attachment?(part)
      return has_content_id?(part) ? [part] : [] if opaque_part?(part)
      return [part] if has_content_id?(part)

      if multipart?(part)
        return cid_resources_from_multipart(part)
      end

      []
    end

    def cid_resources_from_multipart(part)
      case mime_type(part)
      when 'multipart/alternative'
        selection = select_from(part)
        return [] if selection.nil? || selection.empty?

        selection.resources + cid_resources(selection.part)
      when 'multipart/related'
        []
      else
        part.parts.flat_map { |child| cid_resources(child) }
      end
    end

    def non_attachment_parts(part)
      part.parts.reject { |child| explicit_attachment?(child) }
    end

    def preferred?(part)
      @preferred_types.include?(mime_type(part))
    end

    def displayable_leaf?(part)
      !Mail::Utilities.blank?(part.body.decoded)
    end

    def multipart?(part)
      part.multipart?
    end

    def opaque_part?(part)
      mime_type(part) == 'message/rfc822'
    end

    def explicit_attachment?(part)
      disposition = part.header[:content_disposition]
      disposition.respond_to?(:disposition_type) &&
        disposition.disposition_type.to_s.casecmp('attachment').zero?
    end

    def mime_type(part)
      normalize_mime_type(part.mime_type || default_mime_type(part))
    end

    def default_mime_type(part)
      return if part.parts.any?

      'text/plain'
    end

    def content_type_parameter(part, name)
      part.content_type_parameters && part.content_type_parameters[name]
    end

    def has_content_id?(part)
      part.respond_to?(:has_content_id?) && part.has_content_id?
    end

    def content_id(part)
      has_content_id?(part) ? part.header[:content_id].content_id : nil
    end

    def normalize_content_id(value)
      value.to_s.sub(/\Acid:/i, '').gsub(/\A\s*<|>\s*\z/, '').strip
    end

    def normalize_mime_type(value)
      value.to_s.split(';', 2).first.to_s.strip.downcase
    end
  end
end
