# frozen_string_literal: false
#
# Copyright (C) 2001, 2002, 2003 by Michael Neumann (mneumann@ntecs.de)
#
# $Id$
#

require "date"
require "xmlrpc/base64"
require "bigdecimal"
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

    def initialize(xml_writer = nil, type_profile: nil)
      @writer = xml_writer || Config.default_writer.new
      @type_profile = type_profile
    end

    # The XMLRPC::TypeProfile used by this encoder, or +nil+ to fall back
    # to the global XMLRPC::Config flags.
    attr_accessor :type_profile


    def methodCall(name, *params)
      name = name.to_s

      if name !~ /[a-zA-Z0-9_.:\/]+/
        raise ArgumentError, "Wrong XML-RPC method-name"
      end

      parameter = params.each_with_index.collect do |param, index|
        @writer.ele("param", conv2value(param, "params[#{index}]"))
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
        resp = params.each_with_index.collect do |param, index|
          @writer.ele("param", conv2value(param, "params[#{index}]"))
        end

        resp = [@writer.ele("params", *resp)]
      else
        if params.size != 1 or params[0] === XMLRPC::FaultException
          raise ArgumentError, "no valid fault-structure given"
        end
        resp = @writer.ele("fault", conv2value(params[0].to_h, "fault"))
      end


      tree = @writer.document(
               @writer.pi("xml", 'version="1.0"'),
               @writer.ele("methodResponse", resp)
             )

      @writer.document_to_str(tree) + "\n"
    end



    private

    def nil_allowed?
      @type_profile ? @type_profile.nil_value? : Config.enable_nil_create?
    end

    def big_integer_allowed?
      @type_profile ? @type_profile.big_integer? : Config.enable_bigint?
    end

    def decimal_allowed?
      @type_profile ? @type_profile.decimal? : false
    end

    def preserve_unknown_extensions?
      @type_profile ? @type_profile.preserve_unknown_extensions? : false
    end

    #
    # Converts a Ruby object into a XML-RPC <code><value></code> tag
    #
    def conv2value(param, path = "value") # :doc:

        val = case param
        when Integer
          # XML-RPC's int is 32bit int; the i8 extension holds 64bit ints.
          # An out-of-range Integer is never squeezed into a smaller tag.
          if param >= -(2**31) and param <= (2**31-1)
            @writer.tag("i4", param.to_s)
          elsif big_integer_allowed? and param >= -(2**63) and param <= (2**63-1)
            @writer.tag("i8", param.to_s)
          elsif big_integer_allowed?
            raise "Integer #{param} at #{path} is too big! Must be signed 64-bit integer!"
          else
            raise "Integer #{param} at #{path} is too big! Must be signed 32-bit integer!"
          end
        when TrueClass, FalseClass
          @writer.tag("boolean", param ? "1" : "0")

        when Symbol
          @writer.tag("string", param.to_s)

        when String
          @writer.tag("string", param)

        when NilClass
          if nil_allowed?
            @writer.ele("nil")
          else
            raise "Wrong type NilClass at #{path}. Not allowed!"
          end

        when Float
          raise "Wrong value #{param} at #{path}. Not allowed!" unless param.finite?
          @writer.tag("double", param.to_s)

        when BigDecimal
          # exact decimal, never routed through Float
          if decimal_allowed?
            @writer.tag("bigdecimal", param.to_s("F"))
          else
            raise "Wrong type BigDecimal at #{path}. Not allowed!"
          end

        when XMLRPC::UnknownValue
          if preserve_unknown_extensions?
            @writer.tag(param.tag, param.content.to_s)
          else
            raise "Wrong type XMLRPC::UnknownValue at #{path}. Not allowed!"
          end

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
              conv2value(value, "#{path}[#{key.inspect}]")
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
          if Config.enable_marshalling? and param.class.included_modules.include? XMLRPC::Marshallable
            # convert Ruby object into Hash
            ret = {"___class___" => param.class.name}
            param.instance_variables.each {|v|
              name = v[1..-1]
              val = param.instance_variable_get(v)

              if val.nil?
                ret[name] = val if nil_allowed?
              else
                ret[name] = val
              end
            }
            return conv2value(ret, path)
          else
            ok, pa = wrong_type(param)
            if ok
              return conv2value(pa, path)
            else
              raise "Wrong type #{param.class} at #{path}!"
            end
          end
        end

        @writer.ele("value", val)
    end

    def wrong_type(value)
      false
    end


  end # class Create

end # module XMLRPC
