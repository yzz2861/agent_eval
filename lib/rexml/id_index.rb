# frozen_string_literal: false

module REXML
  class DuplicateIDError < StandardError
  end

  class IDIndex
    include Enumerable

    def initialize(document)
      @document = document
      @elements = {}
    end

    def [](id)
      elements = @elements[id]
      return nil if elements.nil?
      raise_duplicate_id(id, elements) if elements.length > 1
      elements.first
    end

    def elements_for(id)
      @elements.fetch(id, []).dup
    end

    def conflict?(id)
      @elements.key?(id) && @elements[id].length > 1
    end

    def conflicts
      @elements.select { |_id, elements| elements.length > 1 }.keys
    end

    def each(&block)
      return to_enum(__method__) unless block_given?
      @elements.each do |id, elements|
        yield(id, elements.first) if elements.length == 1
      end
    end

    def index_element(element)
      return unless element.attributes

      element.attributes.each_attribute do |attribute|
        add_attribute(attribute)
      end
      add_dtd_default_id(element)
    end

    def unindex_element(element)
      return unless element.attributes

      element.attributes.each_attribute do |attribute|
        remove(attribute.element, attribute.expanded_name, attribute.value)
      end
      remove_dtd_default_id(element)
    end

    def index_node(node)
      case node
      when DocType, AttlistDecl
        rebuild
      when Element
        index_subtree(node)
      end
    end

    def unindex_node(node)
      case node
      when DocType, AttlistDecl
        rebuild
      when Element
        unindex_subtree(node)
      end
    end

    def rebuild
      @elements.clear
      root = @document.root
      index_subtree(root) if root
    end

    private

    def index_subtree(element)
      return unless element.elements
      index_element(element)
      element.each_element do |child|
        index_subtree(child)
      end
    end

    def unindex_subtree(element)
      return unless element.elements
      unindex_element(element)
      element.each_element do |child|
        unindex_subtree(child)
      end
    end

    def add_attribute(attribute)
      element = attribute.element
      return unless element&.document&.equal?(@document)
      return unless id_attribute?(element, attribute.expanded_name)

      add(element, attribute.value)
    end

    def add_dtd_default_id(element)
      doctype = @document.doctype
      return unless doctype

      doctype.id_attributes_for(element).each do |name, value|
        next if element.attributes.key?(name)
        add(element, value)
      end
    end

    def remove_dtd_default_id(element)
      doctype = @document.doctype
      return unless doctype

      id_attributes = doctype.id_attributes_for(element)
      return if id_attributes.empty?

      id_attributes.each do |name, value|
        next if element.attributes.key?(name)
        remove(element, name, value)
      end
    end

    def id_attribute?(element, name)
      name == "xml:id" || @document.doctype&.id_attribute?(element.expanded_name, name)
    end

    def add(element, value)
      elements = @elements[value] ||= []
      elements << element unless elements.include?(element)
    end

    def remove(element, _name, value)
      elements = @elements[value]
      return unless elements

      elements.delete(element)
      @elements.delete(value) if elements.empty?
    end

    def raise_duplicate_id(id, elements)
      locations = elements.map(&:xpath).join(", ")
      raise DuplicateIDError, "duplicate ID #{id.inspect}: #{locations}"
    end
  end
end
