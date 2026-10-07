# frozen_string_literal: false
# Copyright (C) 2001, 2002, 2003 by Michael Neumann (mneumann@ntecs.de)
#
# $Id$
#


require "date"
require "xmlrpc/base64"
require "xmlrpc/datetime"
require "xmlrpc/decimal"
require "xmlrpc/type_profile"


module XMLRPC # :nodoc:

  # Raised when the remote procedure returns a fault-structure, which has two
  # accessor-methods +faultCode+ an Integer, and +faultString+ a String.
  class FaultException < StandardError
    attr_reader :faultCode, :faultString

    # Creates a new XMLRPC::FaultException instance.
    #
    # +faultString+ is passed to StandardError as the +msg+ of the Exception.
    def initialize(faultCode, faultString)
      @faultCode   = faultCode
      @faultString = faultString
      super(@faultString)
    end

    # The +faultCode+ and +faultString+ of the exception in a Hash.
    def to_h
      {"faultCode" => @faultCode, "faultString" => @faultString}
    end
  end

  # Helper class used to convert types.
  module Convert

    # Converts a String to an Integer
    #
    # See also String.to_i
    def self.int(str)
      str.to_i
    end

    # Converts a String to +true+ or +false+
    #
    # Raises an exception if +str+ is not +0+ or +1+
    def self.boolean(str)
      case str
      when "0" then false
      when "1" then true
      else
        raise "RPC-value of type boolean is wrong"
      end
    end

    # Converts a String to a Float
    #
    # See also String.to_f
    def self.double(str)
      str.to_f
    end

    # Converts a the given +str+ to a +dateTime.iso8601+ formatted date.
    #
    # Raises an exception if the String isn't in +dateTime.iso8601+ format.
    #
    # See also, XMLRPC::DateTime
    def self.dateTime(str)
      case str
      when /^(-?\d\d\d\d)-?(\d\d)-?(\d\d)T(\d\d):(\d\d):(\d\d)(?:Z|([+-])(\d\d):?(\d\d))?$/
        a = [$1, $2, $3, $4, $5, $6].collect{|i| i.to_i}
        if $7
          ofs = $8.to_i*3600 + $9.to_i*60
          ofs = -ofs if $7=='+'
          utc = Time.utc(*a) + ofs
          a = [ utc.year, utc.month, utc.day, utc.hour, utc.min, utc.sec ]
        end
        XMLRPC::DateTime.new(*a)
      when /^(-?\d\d)-?(\d\d)-?(\d\d)T(\d\d):(\d\d):(\d\d)(Z|([+-]\d\d):(\d\d))?$/
        a = [$1, $2, $3, $4, $5, $6].collect{|i| i.to_i}
        if a[0] < 70
          a[0] += 2000
        else
          a[0] += 1900
        end
        if $7
          ofs = $8.to_i*3600 + $9.to_i*60
          ofs = -ofs if $7=='+'
          utc = Time.utc(*a) + ofs
          a = [ utc.year, utc.month, utc.day, utc.hour, utc.min, utc.sec ]
        end
        XMLRPC::DateTime.new(*a)
      else
        raise "wrong dateTime.iso8601 format " + str
      end
    end

    # Decodes the given +str+ using XMLRPC::Base64.decode
    def self.base64(str)
      XMLRPC::Base64.decode(str)
    end

    # Converts the given +hash+ to a marshalled object.
    #
    # Returns the given +hash+ if an exception occurs.
    def self.struct(hash)
      # convert to marshalled object
      klass = hash["___class___"]
      if klass.nil? or not Config.enable_marshalling?
        hash
      else
        begin
          mod = Module
          klass.split("::").each {|const| mod = mod.const_get(const.strip)}
          return hash unless mod.included_modules.include?(XMLRPC::Marshallable)

          obj = mod.allocate

          hash.delete "___class___"
          hash.each {|key, value|
            obj.instance_variable_set("@#{ key }", value) if key =~ /^([a-zA-Z_]\w*)$/
          }
          obj
        rescue
          hash
        end
      end
    end

    # Converts the given +hash+ to an XMLRPC::FaultException object by passing
    # the +faultCode+ and +faultString+ attributes of the Hash to
    # XMLRPC::FaultException.new
    #
    # Raises an Exception if the given +hash+ doesn't meet the requirements.
    # Those requirements being:
    # * 2 keys
    # * <code>'faultCode'</code> key is an Integer
    # * <code>'faultString'</code> key is a String
    def self.fault(hash)
      if hash.kind_of? Hash and hash.size == 2 and
        hash.has_key? "faultCode" and hash.has_key? "faultString" and
        hash["faultCode"].kind_of? Integer and hash["faultString"].kind_of? String

        XMLRPC::FaultException.new(hash["faultCode"], hash["faultString"])
      else
        raise "wrong fault-structure: #{hash.inspect}"
      end
    end

  end # module Convert

  # Parser for XML-RPC call and response
  module XMLParser

    # Shared helpers for parsers that accept an optional
    # XMLRPC::TypeProfile. When no profile is set, the global
    # XMLRPC::Config flags and the historic defaults apply.
    module ProfileAware

      # The XMLRPC::TypeProfile of this parser, or +nil+ when the global
      # XMLRPC::Config flags are used.
      attr_accessor :type_profile

      private

      def profile_allow_nil?
        @type_profile ? @type_profile.allow_nil? : Config.enable_nil_parser?
      end

      def profile_allow_i8?
        @type_profile ? @type_profile.allow_i8? : true
      end

      def profile_allow_decimal?
        @type_profile ? @type_profile.allow_decimal? : false
      end

      def profile_keep_unknown?
        @type_profile ? @type_profile.keep_unknown_extension? : false
      end

    end

    class AbstractTreeParser
      include ProfileAware

      def parseMethodResponse(str)
        methodResponse_document(createCleanedTree(str))
      end

      def parseMethodCall(str)
        methodCall_document(createCleanedTree(str))
      end

      private

      # Removes all whitespaces but in the tags i4, i8, int, boolean....
      # and all comments
      def removeWhitespacesAndComments(node)
        remove = []
        childs = node.childNodes.to_a
        childs.each do |nd|
          case _nodeType(nd)
          when :TEXT
            # TODO: add nil?
            unless %w(i4 i8 int boolean string double dateTime.iso8601 base64).include? node.nodeName

               if node.nodeName == "value"
                 if not node.childNodes.to_a.detect {|n| _nodeType(n) == :ELEMENT}.nil?
                   remove << nd if nd.nodeValue.strip == ""
                 end
               else
                 remove << nd if nd.nodeValue.strip == ""
               end
            end
          when :COMMENT
            remove << nd
          else
            removeWhitespacesAndComments(nd)
          end
        end

        remove.each { |i| node.removeChild(i) }
      end


      def nodeMustBe(node, name)
        cmp = case name
        when Array
          name.include?(node.nodeName)
        when String
          name == node.nodeName
        else
          raise "error"
        end

        if not cmp
          raise "wrong xml-rpc (name)"
        end

        node
      end

      # Returns, when successfully the only child-node
      def hasOnlyOneChild(node, name=nil)
        if node.childNodes.to_a.size != 1
          raise "wrong xml-rpc (size)"
        end
        if name != nil
          nodeMustBe(node.firstChild, name)
        end
      end


      def assert(b)
        if not b
          raise "assert-fail"
        end
      end

      # The node `node` has empty string or string
      def text_zero_one(node)
        nodes = node.childNodes.to_a.size

        if nodes == 1
          text(node.firstChild)
        elsif nodes == 0
          ""
        else
          raise "wrong xml-rpc (size)"
        end
      end


      def integer(node, path)
        #TODO: check string for float because to_i returnsa
        #      0 when wrong string
         nodeMustBe(node, %w(i4 int))
        hasOnlyOneChild(node)

        Convert.int(text(node.firstChild))
      end

      def integer8(node, path)
        nodeMustBe(node, "i8")
        unless profile_allow_i8?
          raise "wrong/unknown XML-RPC type 'i8' at #{path}"
        end
        hasOnlyOneChild(node)

        Convert.int(text(node.firstChild))
      end

      def decimal(node, path)
        nodeMustBe(node, "decimal")
        unless profile_allow_decimal?
          raise "wrong/unknown XML-RPC type 'decimal' at #{path}"
        end
        hasOnlyOneChild(node)

        begin
          XMLRPC::Decimal.new(text(node.firstChild))
        rescue ArgumentError => e
          raise ArgumentError, "#{e.message} (at #{path})"
        end
      end

      def boolean(node, path)
        nodeMustBe(node, "boolean")
        hasOnlyOneChild(node)

        begin
          Convert.boolean(text(node.firstChild))
        rescue RuntimeError => e
          raise "#{e.message} (at #{path})"
        end
      end

      def v_nil(node, path)
        nodeMustBe(node, "nil")
        assert( node.childNodes.to_a.size == 0 )
        nil
      end

      def string(node, path)
        nodeMustBe(node, "string")
        text_zero_one(node)
      end

      def double(node, path)
        #TODO: check string for float because to_f returnsa
        #      0.0 when wrong string
        nodeMustBe(node, "double")
        hasOnlyOneChild(node)

        Convert.double(text(node.firstChild))
      end

      def dateTime(node, path)
        nodeMustBe(node, "dateTime.iso8601")
        hasOnlyOneChild(node)

        begin
          Convert.dateTime( text(node.firstChild) )
        rescue RuntimeError => e
          raise "#{e.message} (at #{path})"
        end
      end

      def base64(node, path)
        nodeMustBe(node, "base64")
        #hasOnlyOneChild(node)

        Convert.base64(text_zero_one(node))
      end

      def member(node, path)
        nodeMustBe(node, "member")
        assert( node.childNodes.to_a.size == 2 )

        n = name(node[0])
        [ n, value(node[1], "#{path}[#{n.inspect}]") ]
      end

      def name(node)
        nodeMustBe(node, "name")
        #hasOnlyOneChild(node)
        text_zero_one(node)
      end

      def array(node, path)
        nodeMustBe(node, "array")
        hasOnlyOneChild(node, "data")
        data(node.firstChild, path)
      end

      def data(node, path)
        nodeMustBe(node, "data")

        node.childNodes.to_a.each_with_index.collect do |val, i|
          value(val, "#{path}[#{i}]")
        end
      end

      def param(node)
        nodeMustBe(node, "param")
        hasOnlyOneChild(node, "value")
        value(node.firstChild)
      end

      def methodResponse(node)
        nodeMustBe(node, "methodResponse")
        hasOnlyOneChild(node, %w(params fault))
        child = node.firstChild

        case child.nodeName
        when "params"
          [ true, params(child,false) ]
        when "fault"
          [ false, fault(child) ]
        else
          raise "unexpected error"
        end

      end

      def methodName(node)
        nodeMustBe(node, "methodName")
        hasOnlyOneChild(node)
        text(node.firstChild)
      end

      def params(node, call=true)
        nodeMustBe(node, "params")

        if call
          node.childNodes.to_a.collect do |n|
            param(n)
          end
        else # response (only one param)
          hasOnlyOneChild(node)
          param(node.firstChild)
        end
      end

      def fault(node)
        nodeMustBe(node, "fault")
        hasOnlyOneChild(node, "value")
        f = value(node.firstChild)
        Convert.fault(f)
      end



      # _nodeType is defined in the subclass
      def text(node)
        assert( _nodeType(node) == :TEXT )
        assert( node.hasChildNodes == false )
        assert( node.nodeValue != nil )

        node.nodeValue.to_s
      end

      def struct(node, path)
        nodeMustBe(node, "struct")

        hash = {}
        node.childNodes.to_a.each do |me|
          n, v = member(me, path)
          hash[n] = v
        end

        Convert.struct(hash)
      end


      def value(node, path="$")
        nodeMustBe(node, "value")
        nodes = node.childNodes.to_a.size
        if nodes == 0
          return ""
        elsif nodes > 1
          raise "wrong xml-rpc (size)"
        end

        child = node.firstChild

        case _nodeType(child)
        when :TEXT
          text_zero_one(node)
        when :ELEMENT
          case child.nodeName
          when "i4", "int"        then integer(child, path)
          when "i8"               then integer8(child, path)
          when "decimal"          then decimal(child, path)
          when "boolean"          then boolean(child, path)
          when "string"           then string(child, path)
          when "double"           then double(child, path)
          when "dateTime.iso8601" then dateTime(child, path)
          when "base64"           then base64(child, path)
          when "struct"           then struct(child, path)
          when "array"            then array(child, path)
          when "nil"
            if profile_allow_nil?
              v_nil(child, path)
            else
              raise "wrong/unknown XML-RPC type 'nil' at #{path}"
            end
          else
            if profile_keep_unknown?
              XMLRPC::UnknownValue.new(child.nodeName, text_zero_one(child))
            else
              raise "wrong/unknown XML-RPC type '#{child.nodeName}' at #{path}"
            end
          end
        else
          raise "wrong type of node"
        end

      end

      def methodCall(node)
        nodeMustBe(node, "methodCall")
        assert( (1..2).include?( node.childNodes.to_a.size ) )
        name = methodName(node[0])

        if node.childNodes.to_a.size == 2
          pa = params(node[1])
        else # no parameters given
          pa = []
        end
        [name, pa]
      end

    end # module TreeParserMixin

    class AbstractStreamParser
      # The XMLRPC::TypeProfile of this parser, or +nil+ when the global
      # XMLRPC::Config flags are used.
      attr_accessor :type_profile

      def parseMethodResponse(str)
        parser = @parser_class.new
        parser.type_profile = @type_profile
        parser.parse(str)
        raise "No valid method response!" if parser.method_name != nil
        if parser.fault != nil
          # is a fault structure
          [false, parser.fault]
        else
          # is a normal return value
          raise "Missing return value!" if parser.params.size == 0
          raise "Too many return values. Only one allowed!" if parser.params.size > 1
          [true, parser.params[0]]
        end
      end

      def parseMethodCall(str)
        parser = @parser_class.new
        parser.type_profile = @type_profile
        parser.parse(str)
        raise "No valid method call - missing method name!" if parser.method_name.nil?
        [parser.method_name, parser.params]
      end
    end

    module StreamParserMixin
      include ProfileAware

      # Element names this parser knows about. Anything else is an
      # unknown extension tag.
      KNOWN_ELEMENT_NAMES = %w(
        methodCall methodResponse methodName params param fault
        value array data struct member name string
        i4 i8 int boolean double decimal dateTime.iso8601 base64 nil
      ).freeze

      attr_reader :params
      attr_reader :method_name
      attr_reader :fault

      def initialize(*a)
        super(*a)
        @params = []
        @values = []
        @val_stack = []

        @names = []
        @name = []

        @structs = []
        @struct = {}

        @method_name = nil
        @fault = nil

        @data = nil

        @containers = []
        @extension_tags = []
      end

      def startElement(name, attrs=[])
        @data = nil
        case name
        when "value"
          @value = nil
        when "nil"
          unless profile_allow_nil?
            raise "wrong/unknown XML-RPC type 'nil' at #{current_path}"
          end
          @value = :nil
        when "array"
          @val_stack << @values
          @values = []
          @containers << [:array, 0]
        when "struct"
          @names << @name
          @name = []

          @structs << @struct
          @struct = {}
          @containers << [:struct, nil]
        else
          if unknown_extension_tag?(name) and @type_profile
            if profile_keep_unknown?
              @extension_tags << name
            else
              raise "wrong/unknown XML-RPC type '#{name}' at #{current_path}"
            end
          end
        end
      end

      def endElement(name)
        @data ||= ""
        case name
        when "string"
          @value = @data
        when "i4", "int"
          @value = convert_scalar { Convert.int(@data) }
        when "i8"
          if profile_allow_i8?
            @value = convert_scalar { Convert.int(@data) }
          else
            raise "wrong/unknown XML-RPC type 'i8' at #{current_path}"
          end
        when "decimal"
          if @type_profile
            if profile_allow_decimal?
              # exact decimal, never converted through Float
              @value = convert_scalar { XMLRPC::Decimal.new(@data) }
            else
              raise "wrong/unknown XML-RPC type 'decimal' at #{current_path}"
            end
          end
          # legacy mode: ignore the tag, the value falls back to its text
        when "boolean"
          @value = convert_scalar { Convert.boolean(@data) }
        when "double"
          @value = convert_scalar { Convert.double(@data) }
        when "dateTime.iso8601"
          @value = convert_scalar { Convert.dateTime(@data) }
        when "base64"
          @value = Convert.base64(@data)
        when "value"
          @value = @data if @value.nil?
          @values << (@value == :nil ? nil : @value)
          if @containers.last and @containers.last[0] == :array
            @containers.last[1] += 1
          end
        when "array"
          @value = @values
          @values = @val_stack.pop
          @containers.pop
        when "struct"
          @value = Convert.struct(@struct)

          @name = @names.pop
          @struct = @structs.pop
          @containers.pop
        when "name"
          @name[0] = @data
          if @containers.last and @containers.last[0] == :struct
            @containers.last[1] = @data
          end
        when "member"
          @struct[@name[0]] = @values.pop

        when "param"
          @params << @values[0]
          @values = []

        when "fault"
          @fault = Convert.fault(@values[0])

        when "methodName"
          @method_name = @data
        else
          if @extension_tags.last == name
            @extension_tags.pop
            @value = XMLRPC::UnknownValue.new(name, @data)
          end
        end

        @data = nil
      end

      private

      def unknown_extension_tag?(name)
        !KNOWN_ELEMENT_NAMES.include?(name)
      end

      # Re-raises a conversion failure with the path of the value.
      def convert_scalar
        yield
      rescue RuntimeError, ArgumentError => e
        raise e.class, "#{e.message} (at #{current_path})"
      end

      # Path of the value currently being parsed, e.g. $["key"][2].
      def current_path
        path = "$"
        @containers.each do |type, key|
          if type == :array
            path += "[#{key}]"
          else
            path += "[#{key.to_s.inspect}]"
          end
        end
        path
      end

      public

      def character(data)
        if @data
          @data << data
        else
          @data = data
        end
      end

    end # module StreamParserMixin

    class REXMLStreamParser < AbstractStreamParser
      def initialize
        require "rexml/document"
        @parser_class = StreamListener
      end

      class StreamListener
        include StreamParserMixin

        alias :tag_start :startElement
        alias :tag_end :endElement
        alias :text :character
        alias :cdata :character

        def method_missing(*a)
          # ignore
        end

        def parse(str)
          REXML::Document.parse_stream(str, self)
        end
      end

    end

    class LibXMLStreamParser < AbstractStreamParser
      def initialize
        require 'libxml-ruby'
        @parser_class = LibXMLStreamListener
      end

      class LibXMLStreamListener
        include StreamParserMixin

        def on_start_element_ns(name, attributes, prefix, uri, namespaces)
          startElement(name)
        end

        def on_end_element_ns(name, prefix, uri)
          endElement(name)
        end

        alias :on_characters :character
        alias :on_cdata_block :character

        def method_missing(*a)
        end

        def parse(str)
          parser = LibXML::XML::SaxParser.string(str)
          parser.callbacks = self
          parser.parse()
        end
      end
    end

    class NokogiriStreamParser < AbstractStreamParser
      def initialize
        require 'nokogiri'
        @parser_class = NokogiriStreamListener
      end

      class NokogiriStreamListener
        include StreamParserMixin

        def self.handler
          # We need to construct this on first use, since we cannot be sure Nokogiri is available
          @handler ||= begin
            Class.new(Nokogiri::XML::SAX::Document) do
              def initialize(parent)
                super()
                @parent = parent
              end

              def start_element_namespace(name, attrs = [], prefix = nil, uri = nil, ns = [])
                @parent.startElement(name, attrs)
              end

              def end_element_namespace(name, prefix = nil, uri = nil)
                @parent.endElement(name)
              end

              def characters(string)
                @parent.character(string)
              end

              def cdata_block(string)
                @parent.character(string)
              end
            end
          end
        end

        def parse(str)
          parser = Nokogiri::XML::SAX::Parser.new(self.class.handler.new(self))
          parser.parse(str)
        end
      end
    end

    Classes = [REXMLStreamParser, LibXMLStreamParser, NokogiriStreamParser]

    # yields an instance of each installed parser
    def self.each_installed_parser
      XMLRPC::XMLParser::Classes.each do |klass|
        begin
          yield klass.new
        rescue LoadError
        end
      end
    end

  end # module XMLParser


end # module XMLRPC
