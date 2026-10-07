# frozen_string_literal: false
# Copyright (C) 2001, 2002, 2003 by Michael Neumann (mneumann@ntecs.de)
#
# $Id$
#


require "date"
require "xmlrpc/base64"
require "xmlrpc/datetime"
require "bigdecimal"
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

    # Converts a String to a BigDecimal, preserving the exact decimal
    # value (the String is never routed through a Float).
    def self.decimal(str)
      BigDecimal(str)
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

    # Marks exceptions whose message already carries a value path. :nodoc:
    PATH_ERROR_MARK = :@xmlrpc_value_path_error

    # Returns a RuntimeError for +error+ whose message includes the +path+
    # of the offending value, e.g. <tt>params[0]["key"][2]</tt>. If +error+
    # already carries a value path it is returned unchanged, so errors from
    # nested arrays/structs are not prefixed twice.
    def self.value_error(path, error) # :nodoc:
      return error if error.instance_variable_get(PATH_ERROR_MARK)
      wrapped = RuntimeError.new("wrong value at #{path}: #{error.message}")
      wrapped.instance_variable_set(PATH_ERROR_MARK, true)
      wrapped.set_backtrace(error.backtrace)
      wrapped
    end

    # Raises a RuntimeError with +message+ prefixed by the value +path+. :nodoc:
    def self.raise_value_error(path, message)
      raise value_error(path, RuntimeError.new(message))
    end

    class AbstractTreeParser

      # The XMLRPC::TypeProfile used by this parser, or +nil+ to fall back
      # to the global XMLRPC::Config flags.
      attr_accessor :type_profile

      def parseMethodResponse(str)
        methodResponse_document(createCleanedTree(str))
      end

      def parseMethodCall(str)
        methodCall_document(createCleanedTree(str))
      end

      private

      def nil_allowed?
        @type_profile ? @type_profile.nil_value? : Config.enable_nil_parser?
      end

      def big_integer_allowed?
        @type_profile ? @type_profile.big_integer? : true
      end

      def decimal_allowed?
        @type_profile ? @type_profile.decimal? : false
      end

      def preserve_unknown_extensions?
        @type_profile ? @type_profile.preserve_unknown_extensions? : false
      end

      # Handles a tag which is not supported by the active type profile,
      # either by raising or by keeping it as a controlled
      # XMLRPC::UnknownValue. The tag name is never resolved to a class.
      def unknown_extension(node)
        if preserve_unknown_extensions?
          XMLRPC::UnknownValue.new(node.nodeName, text_zero_one(node))
        else
          raise "wrong/unknown XML-RPC type '#{node.nodeName}'"
        end
      end

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


      def integer(node)
        #TODO: check string for float because to_i returnsa
        #      0 when wrong string
         nodeMustBe(node, %w(i4 i8 int))
        hasOnlyOneChild(node)

        Convert.int(text(node.firstChild))
      end

      def boolean(node)
        nodeMustBe(node, "boolean")
        hasOnlyOneChild(node)

        Convert.boolean(text(node.firstChild))
      end

      def v_nil(node)
        nodeMustBe(node, "nil")
        assert( node.childNodes.to_a.size == 0 )
        nil
      end

      def string(node)
        nodeMustBe(node, "string")
        text_zero_one(node)
      end

      def double(node)
        #TODO: check string for float because to_f returnsa
        #      0.0 when wrong string
        nodeMustBe(node, "double")
        hasOnlyOneChild(node)

        Convert.double(text(node.firstChild))
      end

      def bigdecimal(node)
        nodeMustBe(node, "bigdecimal")
        hasOnlyOneChild(node)

        Convert.decimal(text(node.firstChild))
      end

      def dateTime(node)
        nodeMustBe(node, "dateTime.iso8601")
        hasOnlyOneChild(node)

        Convert.dateTime( text(node.firstChild) )
      end

      def base64(node)
        nodeMustBe(node, "base64")
        #hasOnlyOneChild(node)

        Convert.base64(text_zero_one(node))
      end

      def member(node, path)
        nodeMustBe(node, "member")
        assert( node.childNodes.to_a.size == 2 )

        [ name(node[0]), value(node[1], "#{path}[#{name(node[0]).inspect}]") ]
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

        node.childNodes.to_a.each_with_index.collect do |val, index|
          value(val, "#{path}[#{index}]")
        end
      end

      def param(node, path="params[0]")
        nodeMustBe(node, "param")
        hasOnlyOneChild(node, "value")
        value(node.firstChild, path)
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
          node.childNodes.to_a.each_with_index.collect do |n, index|
            param(n, "params[#{index}]")
          end
        else # response (only one param)
          hasOnlyOneChild(node)
          param(node.firstChild, "params[0]")
        end
      end

      def fault(node)
        nodeMustBe(node, "fault")
        hasOnlyOneChild(node, "value")
        f = value(node.firstChild, "fault")
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


      def value(node, path="value")
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
          when "i4", "int"        then integer(child)
          when "i8"
            if big_integer_allowed?
              integer(child)
            else
              unknown_extension(child)
            end
          when "boolean"          then boolean(child)
          when "string"           then string(child)
          when "double"           then double(child)
          when "bigdecimal"
            if decimal_allowed?
              bigdecimal(child)
            else
              unknown_extension(child)
            end
          when "dateTime.iso8601" then dateTime(child)
          when "base64"           then base64(child)
          when "struct"           then struct(child, path)
          when "array"            then array(child, path)
          when "nil"
            if nil_allowed?
              v_nil(child)
            else
              unknown_extension(child)
            end
          else
            unknown_extension(child)
          end
        else
          raise "wrong type of node"
        end

      rescue RuntimeError => e
        raise XMLParser.value_error(path, e)
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
      # The XMLRPC::TypeProfile used by this parser, or +nil+ to fall back
      # to the global XMLRPC::Config flags.
      attr_accessor :type_profile

      def parseMethodResponse(str)
        parser = @parser_class.new
        parser.type_profile = @type_profile if @type_profile
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
        parser.type_profile = @type_profile if @type_profile
        parser.parse(str)
        raise "No valid method call - missing method name!" if parser.method_name.nil?
        [parser.method_name, parser.params]
      end
    end

    module StreamParserMixin
      attr_reader :params
      attr_reader :method_name
      attr_reader :fault

      # The XMLRPC::TypeProfile used by this parser, or +nil+ to fall back
      # to the global XMLRPC::Config flags.
      attr_accessor :type_profile

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

        @type_profile = nil
        @containers = []
        @path_root = "params[0]"
        @in_value = false
        @unknown_tag = nil
      end

      private

      def nil_allowed?
        @type_profile ? @type_profile.nil_value? : Config.enable_nil_parser?
      end

      def big_integer_allowed?
        @type_profile ? @type_profile.big_integer? : true
      end

      def decimal_allowed?
        @type_profile ? @type_profile.decimal? : false
      end

      def preserve_unknown_extensions?
        @type_profile ? @type_profile.preserve_unknown_extensions? : false
      end

      # Path of the value currently being decoded,
      # e.g. <tt>params[0]["key"][2]</tt>.
      def current_path
        path = @path_root.dup
        @containers.each do |kind, key|
          case kind
          when :array  then path << "[#{key}]"
          when :struct then path << "[#{key.inspect}]"
          end
        end
        path
      end

      public

      def startElement(name, attrs=[])
        @data = nil
        case name
        when "value"
          @value = nil
          @in_value = true
        when "nil"
          if nil_allowed?
            @value = :nil
          elsif preserve_unknown_extensions?
            @value = XMLRPC::UnknownValue.new("nil", nil)
          else
            XMLParser.raise_value_error(current_path, "wrong/unknown XML-RPC type 'nil'")
          end
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
        when "param"
          @path_root = "params[#{@params.size}]"
        when "fault"
          @path_root = "fault"
        when "methodCall", "methodResponse", "params", "data", "member",
             "name", "methodName", "string", "i4", "int", "i8", "boolean",
             "double", "dateTime.iso8601", "base64", "bigdecimal"
          # known tag, nothing to do
        else
          # a tag not covered by the active type profile; it is rejected
          # or kept as a controlled XMLRPC::UnknownValue, but never
          # resolved to a Ruby class by name
          if @type_profile and @in_value
            if preserve_unknown_extensions?
              @unknown_tag = name
            else
              XMLParser.raise_value_error(current_path, "wrong/unknown XML-RPC type '#{name}'")
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
          @value = Convert.int(@data)
        when "i8"
          if big_integer_allowed?
            @value = Convert.int(@data)
          elsif preserve_unknown_extensions?
            @value = XMLRPC::UnknownValue.new("i8", @data)
          else
            XMLParser.raise_value_error(current_path, "wrong/unknown XML-RPC type 'i8'")
          end
        when "boolean"
          @value = Convert.boolean(@data)
        when "double"
          @value = Convert.double(@data)
        when "bigdecimal"
          if decimal_allowed?
            @value = Convert.decimal(@data)
          elsif @type_profile and preserve_unknown_extensions?
            @value = XMLRPC::UnknownValue.new("bigdecimal", @data)
          elsif @type_profile
            XMLParser.raise_value_error(current_path, "wrong/unknown XML-RPC type 'bigdecimal'")
          end
        when "dateTime.iso8601"
          @value = Convert.dateTime(@data)
        when "base64"
          @value = Convert.base64(@data)
        when "value"
          @value = @data if @value.nil?
          @values << (@value == :nil ? nil : @value)
          @in_value = false
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
          if @unknown_tag and @unknown_tag == name
            @value = XMLRPC::UnknownValue.new(name, @data)
            @unknown_tag = nil
          end
        end

        @data = nil
      rescue RuntimeError => e
        raise XMLParser.value_error(current_path, e)
      end

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
