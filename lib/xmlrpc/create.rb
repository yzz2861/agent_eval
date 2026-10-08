# frozen_string_literal: false
#
# Copyright (C) 2001, 2002, 2003 by Michael Neumann (mneumann@ntecs.de)
#
# $Id$
#

require "date"
require "xmlrpc/base64"

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

    def initialize(xml_writer = nil)
      @writer = xml_writer || Config.default_writer.new
    end


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

    # Streams a XML-RPC methodCall document instead of building the whole
    # string. Yields each piece, so parameters wrapped with
    # XMLRPC::Base64.stream can be encoded directly from their source IO.
    # Returns an Enumerator when no block is given.
    def methodCall_stream(name, *params)
      name = name.to_s
      if name !~ /[a-zA-Z0-9_.:\/]+/
        raise ArgumentError, "Wrong XML-RPC method-name"
      end
      return enum_for(:methodCall_stream, name, *params) unless block_given?
      emit_method_call(name, params) { |piece| yield piece }
    end

    # Streams a XML-RPC methodResponse document. See #methodCall_stream.
    # Returns an Enumerator when no block is given.
    def methodResponse_stream(is_ret, *params)
      unless is_ret
        if params.size != 1 or params[0] === XMLRPC::FaultException
          raise ArgumentError, "no valid fault-structure given"
        end
      end
      return enum_for(:methodResponse_stream, is_ret, *params) unless block_given?
      emit_method_response(is_ret, params) { |piece| yield piece }
    end



    private

    #
    # Converts a Ruby object into a XML-RPC <code><value></code> tag
    #
    def conv2value(param) # :doc:

        val = case param
        when Integer
          # XML-RPC's int is 32bit int
          if Config.enable_bigint?
            @writer.tag("i4", param.to_s)
          else
            if param >= -(2**31) and param <= (2**31-1)
              @writer.tag("i4", param.to_s)
            else
              raise "Integer is too big! Must be signed 32-bit integer!"
            end
          end
        when TrueClass, FalseClass
          @writer.tag("boolean", param ? "1" : "0")

        when Symbol
          @writer.tag("string", param.to_s)

        when String
          @writer.tag("string", param)

        when NilClass
          if Config.enable_nil_create?
            @writer.ele("nil")
          else
            raise "Wrong type NilClass. Not allowed!"
          end

        when Float
          raise "Wrong value #{param}. Not allowed!" unless param.finite?
          @writer.tag("double", param.to_s)

        when Struct
          h = param.members.collect do |key|
            value = param[key]
            @writer.ele("member",
              @writer.tag("name", key.to_s),
              conv2value(value)
            )
          end

          @writer.ele("struct", *h)

        when Hash
          h = param.collect do |key, value|
            @writer.ele("member",
              @writer.tag("name", key.to_s),
              conv2value(value)
            )
          end

          @writer.ele("struct", *h)

        when Array
          a = param.collect {|v| conv2value(v) }

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

        when XMLRPC::Base64::Stream
          @writer.tag("base64", param.encoded)

        else
          if Config.enable_marshalling? and param.class.included_modules.include? XMLRPC::Marshallable
            # convert Ruby object into Hash
            ret = {"___class___" => param.class.name}
            param.instance_variables.each {|v|
              name = v[1..-1]
              val = param.instance_variable_get(v)

              if val.nil?
                ret[name] = val if Config.enable_nil_create?
              else
                ret[name] = val
              end
            }
            return conv2value(ret)
          else
            ok, pa = wrong_type(param)
            if ok
              return conv2value(pa)
            else
              raise "Wrong type!"
            end
          end
        end

        @writer.ele("value", val)
    end

    def wrong_type(value)
      false
    end

    # Emits the pieces of a methodCall document, tracking owned Base64
    # streams so they are closed on completion, failure or early stop.
    def emit_method_call(name, params)
      active = collect_owned_streams(params)
      begin
        yield @writer.pi("xml", 'version="1.0"')
        yield "<methodCall>"
        yield "<methodName>" + @writer.text(name) + "</methodName>"
        yield "<params>"
        params.each do |param|
          yield "<param>"
          stream_value(param, active) { |piece| yield piece }
          yield "</param>"
        end
        yield "</params>"
        yield "</methodCall>"
        yield "\n"
      ensure
        active.each { |stream| stream.close! }
      end
    end

    def emit_method_response(is_ret, params)
      values = is_ret ? params : [params[0].to_h]
      active = collect_owned_streams(values)
      begin
        yield @writer.pi("xml", 'version="1.0"')
        yield "<methodResponse>"
        if is_ret
          yield "<params>"
          params.each do |param|
            yield "<param>"
            stream_value(param, active) { |piece| yield piece }
            yield "</param>"
          end
          yield "</params>"
        else
          yield "<fault>"
          stream_value(params[0].to_h, active) { |piece| yield piece }
          yield "</fault>"
        end
        yield "</methodResponse>"
        yield "\n"
      ensure
        active.each { |stream| stream.close! }
      end
    end

    def collect_owned_streams(values, found = [])
      values.each do |value|
        case value
        when XMLRPC::Base64::Stream
          found << value if value.close?
        when Hash
          collect_owned_streams(value.values, found)
        when Struct
          collect_owned_streams(value.members.map { |k| value[k] }, found)
        when Array
          collect_owned_streams(value, found)
        end
      end
      found
    end

    def stream_value(param, active = nil)
      case param
      when XMLRPC::Base64::Stream
        active << param if active && param.close?
        yield "<value><base64>"
        param.each_chunk { |piece| yield piece }
        yield "</base64></value>"
      when Hash
        yield "<value><struct>"
        param.each do |key, value|
          yield "<member><name>" + @writer.text(key.to_s) + "</name>"
          stream_value(value, active) { |piece| yield piece }
          yield "</member>"
        end
        yield "</struct></value>"
      when Struct
        yield "<value><struct>"
        param.members.each do |key|
          yield "<member><name>" + @writer.text(key.to_s) + "</name>"
          stream_value(param[key], active) { |piece| yield piece }
          yield "</member>"
        end
        yield "</struct></value>"
      when Array
        yield "<value><array><data>"
        param.each { |v| stream_value(v, active) { |piece| yield piece } }
        yield "</data></array></value>"
      else
        yield @writer.document_to_str(conv2value(param))
      end
    end


  end # class Create

end # module XMLRPC
