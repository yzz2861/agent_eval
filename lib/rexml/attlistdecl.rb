# frozen_string_literal: false
#vim:ts=2 sw=2 noexpandtab:
require_relative 'child'
require_relative 'source'

module REXML
  # This class needs:
  # * Documentation
  # * Work!  Not all types of attlists are intelligently parsed, so we just
  # spew back out what we get in.  This works, but it would be better if
  # we formatted the output ourselves.
  #
  # AttlistDecls provide *just* enough support to allow namespace
  # declarations.  If you need some sort of generalized support, or have an
  # interesting idea about how to map the hideous, terrible design of DTD
  # AttlistDecls onto an intuitive Ruby interface, let me know.  I'm desperate
  # for anything to make DTDs more palateable.
  class AttlistDecl < Child
    include Enumerable

    # Patterns used to extract attribute types from the raw declaration
    # contents.  These mirror REXML::Parsers::BaseParser; they are
    # duplicated here so that this file does not need to load the parser.
    NAMECHAR = '[\-\w\.:]' # :nodoc:
    NAME = "([\\w:]#{NAMECHAR}*)" # :nodoc:
    NMTOKEN = "(?:#{NAMECHAR})+" # :nodoc:
    REFERENCE = "&(?:#{NAME};|#\\d+;|#x[0-9a-fA-F]+;)" # :nodoc:
    ENUMERATION = "\\(\\s*#{NMTOKEN}(?:\\s*\\|\\s*#{NMTOKEN})*\\s*\\)" # :nodoc:
    NOTATIONTYPE = "NOTATION\\s+\\(#{NAME}(?:\\s*\\|\\s*#{NAME})*\\s*\\)" # :nodoc:
    ENUMERATEDTYPE = "(?:(?:#{NOTATIONTYPE})|(?:#{ENUMERATION}))" # :nodoc:
    ATTTYPE = "(CDATA|ID|IDREF|IDREFS|ENTITY|ENTITIES|NMTOKEN|NMTOKENS|#{ENUMERATEDTYPE})" # :nodoc:
    ATTVALUE = "(?:\"((?:[^<&\"]|#{REFERENCE})*)\")|(?:'((?:[^<&']|#{REFERENCE})*)')" # :nodoc:
    DEFAULTDECL = "(#REQUIRED|#IMPLIED|(?:(#FIXED\\s+)?#{ATTVALUE}))" # :nodoc:
    ATTDEF = "\\s+#{NAME}\\s+#{ATTTYPE}\\s+#{DEFAULTDECL}" # :nodoc:
    ATTDEF_RE = /#{ATTDEF}/ # :nodoc:

    # What is this?  Got me.
    attr_reader :element_name

    # Create an AttlistDecl, pulling the information from a Source.  Notice
    # that this isn't very convenient; to create an AttlistDecl, you basically
    # have to format it yourself, and then have the initializer parse it.
    # Sorry, but for the foreseeable future, DTD support in REXML is pretty
    # weak on convenience.  Have I mentioned how much I hate DTDs?
    def initialize(source)
      super()
      if (source.kind_of? Array)
        @element_name, @pairs, @contents = *source
      end
    end

    # Access the attlist attribute/value pairs.
    #  value = attlist_decl[ attribute_name ]
    def [](key)
      @pairs[key]
    end

    # Whether an attlist declaration includes the given attribute definition
    #  if attlist_decl.include? "xmlns:foobar"
    def include?(key)
      @pairs.keys.include? key
    end

    # Returns a Hash mapping each attribute name declared in this
    # declaration to its declared type.  For example, the declaration:
    #
    #   <!ATTLIST item uid ID #IMPLIED label CDATA #REQUIRED>
    #
    # gives:
    #
    #   {"uid" => "ID", "label" => "CDATA"}
    #
    # An AttlistDecl built by hand from an attribute name/value list
    # carries no type information and returns an empty Hash.
    def attribute_types
      @attribute_types ||= begin
        types = {}
        @contents.to_s.scan(ATTDEF_RE) do |name, type, *|
          types[name] = type
        end
        types
      end
    end

    # Iterate over the key/value pairs:
    #  attlist_decl.each { |attribute_name, attribute_value| ... }
    def each(&block)
      @pairs.each(&block)
    end

    # Write out exactly what we got in.
    def write out, indent=-1
      out << @contents
    end

    def node_type
      :attlistdecl
    end
  end
end
