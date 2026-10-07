# frozen_string_literal: false
#
# Copyright (C) 2001, 2002, 2003 by Michael Neumann (mneumann@ntecs.de)
#
# $Id$
#

require "date"
require "xmlrpc/base64"
require "xmlrpc/decimal"
require "xmlrpc/type_profile"

module XMLRPC # :nodoc:

  module XMLWriter

    module Element
      def ele(name, *children)
        element(name, nil, *children)
      end

      def tag(name, txt)
        element(name, nil, text(txt))
      end
    end


    class Simple
      include Element

      def document_to_str(doc)
        doc
      end

      def document(*params)
        params.join("")
      end

      def pi(name, *params)
        "<?#{name} " + params.join(" ") + " ?>"
      end

      def element(name, attrs, *children)
        raise "attributes not yet implemented" unless attrs.nil?
        if children.empty?
          "<#{name}/>"
        else
          "<#{name}>" + children.join("") + "</#{name}>"
        end
      end

      def text(txt)
        cleaned = txt.dup
        cleaned.gsub!(/&/, '&amp;')
        cleaned.gsub!(/</, '&lt;')
        cleaned.gsub!(/>/, '&gt;')
        cleaned
      end

    end # class Simple


    class XMLParser
      include Element

      def initialize
        require "xmltreebuilder"
      end

      def document_to_str(doc)
        doc.to_s
      end

      def document(*params)
        XML::SimpleTree::Document.new(*params)
      end

      def pi(name, *params)
        XML::SimpleTree::ProcessingInstruction.new(name, *params)
      end

      def element(name, attrs, *children)
        XML::SimpleTree::Element.new(name, attrs, *children)
      end

      def text(txt)
        XML::SimpleTree::Text.new(txt)
      end

    end # class XMLParser

    Classes = [Simple, XMLParser]

    # yields an instance of each installed XML writer
    def self.each_installed_writer
      XMLRPC::XMLWriter::Classes.each do |klass|
        begin
          yield klass.new
        rescue LoadError
        end
      end
    end

  end # module XMLWriter

  # Creates XML-RPC call/response documents
  #
  class Create

    # Creates a new XMLRPC::Create instance.
    #
    # +xml_writer+ is an instance of a class from module XMLRPC::XMLWriter.
    #
    # When +type_profile+ (an XMLRPC::TypeProfile) is given, the encoder
    # follows that profile instead of the global XMLRPC::Config flags.
    def initialize(xml_writer = nil, type_profile: nil)
      @writer = xml_writer || Config.default_writer.new
      @type_profile = type_profile
    end

    # The XMLRPC::TypeProfile of this encoder, or +nil+ when the global
    # XMLRPC::Config flags are used.
    attr_accessor :type_profile


    def methodCall(name, *params)
      name = name.to_s

      if name !~ /[a-zA-Z0-9_.:\/]+/
        raise ArgumentError, "Wrong XML-RPC method-name"
      end

      parameter = params.collect do |param|
        @writer.ele("param", conv2value(param))
      end

      tree = @writer.document(
               @writer.pi("xml", 'version="1.0"'),
               @writer.ele("methodCall",
                 @writer.tag("methodName", name),
                 @writer.ele("params", *parameter)
               )
             )

      @writer.document_to_str(tree) + "\n"
    end



    #
    # Generates a XML-RPC methodResponse document
    #
    # When +is_ret+ is +false+ then the +params+ array must
    # contain only one element, which is a structure
    # of a fault return-value.
    #
    # When +is_ret+ is +true+ then a normal
    # return-value of all the given +params+ is created.
    #
    def methodResponse(is_ret, *params)

      if is_ret
        resp = params.collect do |param|
          @writer.ele("param", conv2value(param))
        end

        resp = [@writer.ele("params", *resp)]
      else
        if params.size != 1 or params[0] === XMLRPC::FaultException
          raise ArgumentError, "no valid fault-structure given"
        end
        resp = @writer.ele("fault", conv2value(params[0].to_h))
      end


      tree = @writer.document(
               @writer.pi("xml", 'version="1.0"'),
               @writer.ele("methodResponse", resp)
             )

      @writer.document_to_str(tree) + "\n"
    end



    private

    def profile_allow_i8?
      @type_profile ? @type_profile.allow_i8? : Config.enable_bigint?
    end

    def profile_allow_nil?
      @type_profile ? @type_profile.allow_nil? : Config.enable_nil_create?
    end

    def profile_allow_decimal?
      @type_profile ? @type_profile.allow_decimal? : false
    end

    def encode_integer(param, path)
      if @type_profile
        tag = @type_profile.integer_tag(param)
        if tag.nil?
          limit = @type_profile.allow_i8? ? "signed 64-bit" : "signed 32-bit"
          raise "Integer #{param} at #{path} is too big! Must be #{limit} integer!"
        end
        @writer.tag(tag, param.to_s)
      else
        # legacy behavior driven by XMLRPC::Config
        if Config.enable_bigint?
          @writer.tag("i4", param.to_s)
        else
          if param >= -(2**31) and param <= (2**31-1)
            @writer.tag("i4", param.to_s)
          else
            raise "Integer #{param} at #{path} is too big! Must be signed 32-bit integer!"
          end
        end
      end
    end

    #
    # Converts a Ruby object into a XML-RPC <code><value></code> tag
    #
    def conv2value(param, path="$") # :doc:

        if defined?(BigDecimal) and param.is_a?(BigDecimal)
          # exact decimal, never converted through Float
          param = XMLRPC::Decimal.new(param.to_s("F"))
        end

        val = case param
        when Integer
          encode_integer(param, path)

        when TrueClass, FalseClass
          @writer.tag("boolean", param ? "1" : "0")

        when Symbol
          @writer.tag("string", param.to_s)

        when String
          @writer.tag("string", param)

        when NilClass
          if profile_allow_nil?
            @writer.ele("nil")
          else
            raise "Wrong type NilClass at #{path}. Not allowed!"
          end

        when XMLRPC::Decimal
          if @type_profile
            if profile_allow_decimal?
              @writer.tag("decimal", param.to_s)
            else
              raise "Wrong type XMLRPC::Decimal at #{path}. Not allowed!"
            end
          else
            return conv_fallback(param, path)
          end

        when Float
          raise "Wrong value #{param} at #{path}. Not allowed!" unless param.finite?
          @writer.tag("double", param.to_s)

        when Struct
          h = param.members.collect do |key|
            value = param[key]
            @writer.ele("member",
              @writer.tag("name", key.to_s),
              conv2value(value, "#{path}[#{key.to_s.inspect}]")
            )
          end

          @writer.ele("struct", *h)

        when Hash
          h = param.collect do |key, value|
            @writer.ele("member",
              @writer.tag("name", key.to_s),
              conv2value(value, "#{path}[#{key.to_s.inspect}]")
            )
          end

          @writer.ele("struct", *h)

        when Array
          a = param.each_with_index.collect {|v, i| conv2value(v, "#{path}[#{i}]") }

          @writer.ele("array",
            @writer.ele("data", *a)
          )

        when Time, Date, ::DateTime
          @writer.tag("dateTime.iso8601", param.strftime("%Y%m%dT%H:%M:%S"))

        when XMLRPC::DateTime
          @writer.tag("dateTime.iso8601",
            format("%.4d%02d%02dT%02d:%02d:%02d", *param.to_a))

        when XMLRPC::Base64
          @writer.tag("base64", param.encoded)

        else
          return conv_fallback(param, path)
        end

        @writer.ele("value", val)
    end

    def conv_fallback(param, path)
      if Config.enable_marshalling? and param.class.included_modules.include? XMLRPC::Marshallable
        # convert Ruby object into Hash
        ret = {"___class___" => param.class.name}
        param.instance_variables.each {|v|
          name = v[1..-1]
          val = param.instance_variable_get(v)

          if val.nil?
            ret[name] = val if profile_allow_nil?
          else
            ret[name] = val
          end
        }
        conv2value(ret, path)
      else
        ok, pa = wrong_type(param)
        if ok
          conv2value(pa, path)
        else
          raise "Wrong type #{param.class} at #{path}!"
        end
      end
    end

    def wrong_type(value)
      false
    end


  end # class Create

end # module XMLRPC
