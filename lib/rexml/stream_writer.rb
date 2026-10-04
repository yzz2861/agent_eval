# frozen_string_literal: true

require_relative "parseexception"
require_relative "text"
require_relative "xmltokens"

module REXML
  # A streaming XML writer.
  #
  # Unlike building an Element tree, StreamWriter emits nodes as the
  # document is being constructed. Start tags are held back only until an
  # attribute can no longer be added to them.
  class StreamWriter
    include XMLTokens

    class UnbalancedTagsError < RuntimeError
    end

    NAME_PATTERN = /\A(?:(#{NCNAME_STR}):)?(#{NCNAME_STR})\z/u
    private_constant :NAME_PATTERN

    XML_NAMESPACE = "http://www.w3.org/XML/1998/namespace"
    private_constant :XML_NAMESPACE

    # Creates a writer that sends XML to +output+. The target must respond
    # to #<<. StreamWriter never closes +output+.
    def initialize(output)
      @output = output
      @document = {namespaces: {"xml" => XML_NAMESPACE},
                   root_closed: false}
      @elements = []
      @finished = false
    end

    # Opens an element and returns the writer. Attributes may be added
    # until text, a comment, or a child element is written.
    def start_element(name)
      name = validate_name(name)
      raise RuntimeError, "document is already finished" if @finished
      raise RuntimeError, "document already has a root element" if @document[:root_closed]
      flush_pending_element unless @elements.empty?
      @elements << {
        name: name,
        prefixes: {},
        namespaces: {},
        attributes: [],
        started: false,
      }
      self
    end

    # Adds an attribute to the current element and returns the writer.
    #
    # A namespace declaration is added with +"xmlns"+ or +"xmlns:prefix"+
    # as the attribute name.
    def attribute(name, value)
      name = validate_name(name)
      element = require_open_element
      raise RuntimeError, "can't add attribute after child content has started" if element[:started]

      value = value.to_s
      validate_xml_chars(value)
      prefix, local_name = split_name(name)

      if prefix == "xmlns" || (prefix.empty? && local_name == "xmlns")
        namespace_prefix = prefix.empty? ? "" : local_name
        add_namespace_declaration(element, namespace_prefix, name, value)
      else
        raise ArgumentError, "the xmlns prefix can't be used for attributes" if prefix == "xmlns"
        add_regular_attribute(element, name, prefix, local_name, value)
      end

      self
    end
    alias_method :attr, :attribute

    # Writes a text node and returns the writer.
    def text(value)
      value = value.to_s
      validate_xml_chars(value)
      flush_pending_element unless @elements.empty?
      raise RuntimeError, "text nodes are not allowed outside an element" if @elements.empty?

      write(escape_text(value))
      self
    end

    # Writes a comment and returns the writer. Comments are allowed inside
    # elements and in the document epilog.
    def comment(value)
      value = value.to_s
      validate_xml_chars(value)
      if value.include?("--") || value.end_with?("-")
        raise ArgumentError, "XML comments can't contain '--' or end with '-'"
      end

      if @elements.empty?
        raise RuntimeError, "document is already finished" if @finished
      else
        flush_pending_element
      end

      write("<!--#{value}-->")
      self
    end

    # Closes +name+, or the current element when +name+ is omitted, and
    # returns the writer.
    def end_element(name = nil)
      raise RuntimeError, "no element is open" if @elements.empty?
      name = validate_name(name) unless name.nil?
      element = @elements.last
      unless name.nil? || element[:name] == name
        raise ArgumentError,
              "expected closing tag for #{element[:name].inspect}, got #{name.inspect}"
      end

      if element[:started]
        write("</#{element[:name]}>")
      else
        write(build_start_tag(element, true))
      end
      @elements.pop
      @document[:root_closed] = true if @elements.empty?
      self
    end
    alias_method :close_element, :end_element

    # Validates that every opened element has been closed and returns the
    # writer. The borrowed output IO is left open.
    def finish
      unless @elements.empty?
        names = @elements.map { |element| element[:name] }
        raise UnbalancedTagsError, "unclosed element(s): #{names.join(', ')}"
      end
      @finished = true
      self
    end

    private

    def require_open_element
      element = @elements.last
      raise RuntimeError, "no element is open" if element.nil?
      element
    end

    def add_namespace_declaration(element, prefix, name, value)
      if prefix == "xml" && value != XML_NAMESPACE
        raise ArgumentError, "the xml prefix must be bound to #{XML_NAMESPACE}"
      end
      if prefix == "xmlns"
        raise ArgumentError, "the xmlns prefix can't be declared"
      end
      if !prefix.empty? && value.empty?
        raise ArgumentError, "namespace prefix #{prefix.inspect} can't be undeclared"
      end
      if element[:prefixes].key?(prefix)
        _existing_name, existing_value = element[:prefixes][prefix]
        unless existing_value == value
          raise ArgumentError, "namespace prefix #{prefix.inspect} can't be bound to both #{existing_value.inspect} and #{value.inspect}"
        end
        raise ArgumentError, "duplicate attribute #{name.inspect}"
      end

      element[:prefixes][prefix] = [name, value]
      element[:namespaces][prefix] = value
      element[:attributes] << [name, value]
    end

    def add_regular_attribute(element, name, prefix, local_name, value)
      if element[:attributes].any? { |attribute_name, _| attribute_name == name }
        raise ArgumentError, "duplicate attribute #{name.inspect}"
      end

      if prefix == "xml"
        namespace = XML_NAMESPACE
      elsif prefix.empty?
        namespace = ""
      elsif element[:namespaces].key?(prefix)
        namespace = element[:namespaces][prefix]
      else
        begin
          namespace = resolve_namespace(prefix)
        rescue REXML::ParseException
          # The prefix may be declared by another attribute before the
          # pending start tag is flushed.
        end
      end
      if namespace
        existing_name = element[:attributes].find do |existing_name, _|
          existing_prefix, existing_local_name = split_name(existing_name)
          next false if existing_prefix == "xmlns"
          next false if existing_prefix.empty? && existing_local_name == "xmlns"
          existing_namespace = attribute_namespace(element, existing_prefix)
          existing_namespace == namespace && existing_local_name == local_name
        end&.first
        if existing_name
          raise ArgumentError,
                "duplicate attribute #{name.inspect} (already defined as #{existing_name.inspect})"
        end
      end

      element[:attributes] << [name, value]
    end

    def attribute_namespace(element, prefix)
      return "" if prefix.empty?
      return XML_NAMESPACE if prefix == "xml"
      return element[:namespaces][prefix] if element[:namespaces].key?(prefix)

      resolve_namespace(prefix)
    end

    def resolve_namespace(prefix)
      @elements.reverse_each do |element|
        return element[:namespaces][prefix] if element[:namespaces].key?(prefix)
      end
      @document[:namespaces][prefix] ||
        raise(REXML::ParseException.new("Undefined prefix #{prefix} found"))
    end

    def flush_pending_element
      element = @elements.last
      return if element.nil? || element[:started]

      resolve_element_namespace(element)
      validate_attribute_keys(element)
      write(build_start_tag(element, false))
      mark_started
    end

    def mark_started
      @elements.last[:started] = true
    end

    def resolve_element_namespace(element)
      prefix, = split_name(element[:name])
      return if prefix.empty?

      namespace = if prefix == "xml"
                    XML_NAMESPACE
                  else
                    resolve_namespace(prefix)
                  end
      return if namespace

      raise REXML::ParseException.new("Undefined prefix #{prefix} found")
    end

    def validate_attribute_keys(element)
      keys = {}
      element[:attributes].each do |name, _value|
        prefix, local_name = split_name(name)
        next if prefix == "xmlns" || (prefix.empty? && local_name == "xmlns")

        namespace = if prefix.empty?
                      ""
                    elsif prefix == "xml"
                      XML_NAMESPACE
                    else
                      element[:namespaces].fetch(prefix) do
                        resolve_namespace(prefix)
                      end
                    end
        key = [namespace, local_name]
        existing_name = keys[key]
        if existing_name
          raise ArgumentError,
                "duplicate attribute #{name.inspect} (already defined as #{existing_name.inspect})"
        end
        keys[key] = name
      end
    end

    def build_start_tag(element, empty)
      parts = ["<", element[:name]]
      element[:attributes].each do |name, value|
        parts << " " << name << "=\"" << escape_attribute(value) << "\""
      end
      parts << (empty ? "/>" : ">")
      parts.join
    end

    def write(content)
      @output << content
    end

    def validate_name(name)
      name = name.to_s
      unless NAME_PATTERN.match?(name)
        raise ArgumentError,
              "name must be \#{PREFIX}:\#{LOCAL_NAME} or \#{LOCAL_NAME}: #{name.inspect}"
      end
      name
    end

    def split_name(name)
      matches = NAME_PATTERN.match(name)
      [matches[1] || "", matches[2]]
    end

    def validate_xml_chars(value)
      unless value.match?(Text::VALID_XML_CHARS)
        raise ArgumentError, "string contains invalid XML characters"
      end
    end

    def escape_text(value)
      Text.normalize(value)
    end

    def escape_attribute(value)
      escape_text(value)
    end
  end
end
