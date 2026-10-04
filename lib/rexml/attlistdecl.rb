# frozen_string_literal: false
#vim:ts=2 sw=2 noexpandtab:
require_relative 'child'
require_relative 'source'
require_relative 'xmltokens'
require 'strscan'

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
    include XMLTokens

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

    # Iterate over the key/value pairs:
    #  attlist_decl.each { |attribute_name, attribute_value| ... }
    def each(&block)
      @pairs.each(&block)
    end

    def attribute_types
      return {} unless @contents

      scanner = StringScanner.new(@contents)
      scanner.skip(/\s*<!ATTLIST/) or return {}
      scanner.scan(/\s+#{NAME_STR}(?=\s)/) or return {}

      types = {}
      type_pattern = /CDATA|IDREFS|IDREF|ID|ENTITIES|ENTITY|NMTOKENS|NMTOKEN|NOTATION\s*\([^)]*\)|\([^)]*\)/
      until scanner.eos?
        scanner.scan(/\s+/)
        name = scanner.scan(/#{NAME_STR}(?=\s)/)
        break if name.nil?

        scanner.scan(/\s+/)
        type = scanner.scan(type_pattern)
        break if type.nil?

        types[name] = type.strip
        scanner.scan_until(/(?=\s+#{NAME_STR}\s+(?:CDATA|IDREFS|IDREF|ID|ENTITIES|ENTITY|NMTOKENS|NMTOKEN|NOTATION|\())/m)
      end
      types
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
