# frozen_string_literal: false

require_relative "undefinednamespaceexception"

module REXML
  # A streaming XML writer that emits markup directly to an output IO,
  # without building a document tree in memory.  Useful when generating
  # large documents while iterating over records.
  #
  #   io = StringIO.new
  #   writer = REXML::StreamWriter.new(io)
  #   writer.start_element("root", "xmlns:p" => "urn:example")
  #   writer.start_element("p:item", "id" => 1)
  #   writer.text("first")
  #   writer.end_element
  #   writer.comment("done")
  #   writer.end_element
  #   writer.finish
  #
  # The writer tracks namespace declarations made with +xmlns+ and
  # +xmlns:prefix+ attributes and keeps them in scope for the element on
  # which they were declared and its descendants.  Element and attribute
  # prefixes must be bound in the current scope.  Attributes are checked
  # for duplicates by expanded name, so two attributes whose prefixes
  # resolve to the same namespace URI and share a local name collide.
  #
  # Attributes may only be added immediately after #start_element; once
  # any child content (text, comment, or a nested element) has been
  # written, the start tag is sealed.
  #
  # If the underlying IO raises while writing, internal state is left
  # untouched, so the failed operation can be retried.  #finish verifies
  # that all elements are balanced and never closes the IO it was given.
  class StreamWriter
    # Raised for API misuse such as unbalanced tags, duplicate
    # attributes, or attributes added after child content.
    class Error < StandardError; end

    # The IO-like object (must respond to +<<+) receiving the output.
    attr_reader :output

    NAME_PATTERN = /\A[A-Za-z_][A-Za-z0-9_.:-]*\z/
    XML_PREFIX_URI = "http://www.w3.org/XML/1998/namespace"

    TEXT_ESCAPES = {
      "&" => "&amp;",
      "<" => "&lt;",
      ">" => "&gt;",
    }
    ATTRIBUTE_ESCAPES = {
      "&" => "&amp;",
      "<" => "&lt;",
      '"' => "&quot;",
    }

    def initialize(output)
      unless output.respond_to?(:<<)
        raise ArgumentError, "output must respond to <<"
      end
      @output = output
      @elements = []
      @scopes = [{"xml" => XML_PREFIX_URI}]
      @pending_tag = nil
      @pending_attributes = nil
      @finished = false
    end

    # Starts an element.  +attributes+, if given, is a hash (or anything
    # responding to +each_pair+) of attribute name/value pairs written
    # onto the new element.  +xmlns+ and +xmlns:prefix+ attributes
    # declare namespaces scoped to this element and its descendants.
    def start_element(name, attributes = nil)
      check_active
      name = check_name(name)
      declarations, ordinary = split_attributes(attributes)
      scope = @scopes.last.merge(declarations)
      resolve_prefix(scope, element_prefix(name))
      close_start_tag
      write("<#{name}")
      @scopes << scope
      @elements << name
      @pending_tag = name
      @pending_attributes = {}
      declarations.each_key do |prefix|
        write_namespace_attribute(prefix)
      end
      ordinary.each do |attribute_name, value|
        attribute(attribute_name, value)
      end
      self
    end

    # Adds an attribute to the most recently started element.  Raises
    # Error if child content has already been written for that element,
    # or if an attribute with the same expanded name already exists.
    def attribute(name, value)
      check_active
      unless @pending_tag
        raise Error,
              "attributes must be added immediately after start_element"
      end
      name = check_name(name)
      value = value.to_s
      if name == "xmlns" || name.start_with?("xmlns:")
        prefix = name == "xmlns" ? "" : name[6..]
        key = [:xmlns, prefix]
        check_duplicate(key, name)
        write(" #{name}=\"#{escape_attribute(value)}\"")
        @scopes.last[prefix] = value
        @pending_attributes[key] = true
      else
        prefix, local = split_name(name)
        uri = prefix ? resolve_prefix(@scopes.last, prefix) : nil
        key = [uri, local]
        check_duplicate(key, name)
        write(" #{name}=\"#{escape_attribute(value)}\"")
        @pending_attributes[key] = true
      end
      self
    end

    # Writes escaped character data.
    def text(string)
      check_active
      close_start_tag
      write(escape_text(string.to_s))
      self
    end

    # Writes an XML comment.  The content must not contain +--+ or end
    # with +-+, per the XML specification.
    def comment(string)
      check_active
      string = string.to_s
      if string.include?("--") || string.end_with?("-")
        raise Error, "comment content must not contain '--' or end with '-'"
      end
      close_start_tag
      write("<!--#{string}-->")
      self
    end

    # Ends the innermost open element.  An empty element is written in
    # self-closing form (<tt><a/></tt>).  If +name+ is given it must
    # match the open element's name.
    def end_element(name = nil)
      check_active
      if @elements.empty?
        raise Error, "no open element to end"
      end
      open = @elements.last
      if name && name != open
        raise Error, "end tag #{name.inspect} does not match open " +                     "element #{open.inspect}"
      end
      if @pending_tag
        write("/>")
        @pending_tag = nil
        @pending_attributes = nil
      else
        write("</#{open}>")
      end
      @elements.pop
      @scopes.pop
      self
    end

    # Verifies that every element has been ended and marks the writer
    # finished.  Returns the output IO, which is left open.  Raises
    # Error if any element is still open.
    def finish
      unless @elements.empty?
        raise Error,
              "unbalanced XML: #{@elements.size} unclosed element(s): " +              "#{@elements.join(', ')}"
      end
      @finished = true
      @output
    end

    def finished?
      @finished
    end

    private

    def check_active
      raise Error, "writer is already finished" if @finished
    end

    def check_name(name)
      name = name.to_s
      unless name.match?(NAME_PATTERN)
        raise Error, "invalid name #{name.inspect}"
      end
      name
    end

    def split_name(name)
      if (index = name.index(":"))
        [name[0...index], name[(index + 1)..]]
      else
        [nil, name]
      end
    end

    def element_prefix(name)
      split_name(name).first
    end

    def resolve_prefix(scope, prefix)
      return nil if prefix.nil?
      uri = scope[prefix]
      if uri.nil?
        raise UndefinedNamespaceException.new(prefix, nil, nil)
      end
      uri
    end

    def split_attributes(attributes)
      declarations = {}
      ordinary = []
      return [declarations, ordinary] if attributes.nil?
      attributes.each_pair do |name, value|
        name = check_name(name)
        if name == "xmlns"
          declarations[""] = value.to_s
        elsif name.start_with?("xmlns:")
          declarations[name[6..]] = value.to_s
        else
          ordinary << [name, value]
        end
      end
      [declarations, ordinary]
    end

    def write_namespace_attribute(prefix)
      name = prefix.empty? ? "xmlns" : "xmlns:#{prefix}"
      key = [:xmlns, prefix]
      check_duplicate(key, name)
      write(" #{name}=\"#{escape_attribute(@scopes.last[prefix])}\"")
      @pending_attributes[key] = true
    end

    def check_duplicate(key, name)
      if @pending_attributes.key?(key)
        raise Error, "duplicate attribute #{name.inspect}"
      end
    end

    def close_start_tag
      return unless @pending_tag
      write(">")
      @pending_tag = nil
      @pending_attributes = nil
    end

    def escape_text(string)
      string.gsub(/[&<>]/, TEXT_ESCAPES)
    end

    def escape_attribute(string)
      string.gsub(/[&<"]/, ATTRIBUTE_ESCAPES)
    end

    def write(markup)
      @output << markup
    end
  end
end
