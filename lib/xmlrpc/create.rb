# frozen_string_literal: false
#
# Copyright (C) 2001, 2002, 2003 by Michael Neumann (mneumann@ntecs.de)
#
# $Id$
#

require "date"
require "xmlrpc/base64"
require "stringio"

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


    class StreamingDocument
      READ_SIZE = 4096

      attr_reader :size

      def initialize(parts, encoders)
        @parts = parts.flatten
        @encoders = encoders
        @pending = nil
        @finished = false
        @position = 0
        @closed = false
        sizes = @parts.map do |part|
          part.respond_to?(:encoded_size) ? part.encoded_size : part.to_s.bytesize
        end
        @size = sizes.include?(nil) ? nil : sizes.inject(0, :+)
      end

      def read(length = nil, outbuf = nil)
        length ||= READ_SIZE
        result = String.new
        result.force_encoding(Encoding::BINARY)

        until result.bytesize >= length
          fill_pending(length - result.bytesize)
          break if @pending.nil? || @pending.empty?
          chunk = @pending.byteslice(0, length - result.bytesize)
          result << chunk
          @pending = @pending.byteslice(chunk.bytesize, @pending.bytesize)
        end

        if result.empty?
          close if @finished
          if outbuf
            outbuf.replace(result)
            return outbuf
          end
          return nil
        end

        outbuf.replace(result) if outbuf
        @position += result.bytesize
        result
      end

      def close
        return if @closed
        @closed = true
        @encoders.each(&:close)
      end

      def eof?
        @finished && (@pending.nil? || @pending.empty?)
      end

      attr_reader :pos
      def lineno
        0
      end

      def close_on_parse_error?
        @encoders.any? { |encoder| encoder.owned_input? }
      end

      private

      def fill_pending(limit)
        while @pending.nil? || @pending.empty?
          part = @parts.first
          break if part.nil?

          if part.respond_to?(:encoded_size)
            chunk = part.read([limit, 1].max)
            if chunk.nil?
              @parts.shift
            else
              @pending = chunk.to_s
            end
          else
            @parts.shift
            @pending = part.to_s
          end
        end

        @finished = true if @parts.empty? && (@pending.nil? || @pending.empty?)
      end
    end


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

      return methodCallStream(name, params) if params.any? { |param| stream_param?(param) }

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

    def methodCallStream(name, params)
      unless @writer.is_a?(XMLWriter::Simple)
        raise ArgumentError, "streaming XML-RPC values require XMLRPC::XMLWriter::Simple"
      end

      name = name.to_s
      if name !~ /[a-zA-Z0-9_.:\/]+/
        raise ArgumentError, "Wrong XML-RPC method-name"
      end

      parts = [@writer.pi("xml", 'version="1.0"'), "<methodCall>", @writer.tag("methodName", name)]
      encoders = []
      stream_document(parts, encoders, params)
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
      return methodResponseStream(is_ret, params) if params.any? { |param| stream_param?(param) }

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

    def methodResponseStream(is_ret, params)
      unless @writer.is_a?(XMLWriter::Simple)
        raise ArgumentError, "streaming XML-RPC values require XMLRPC::XMLWriter::Simple"
      end

      parts = [@writer.pi("xml", 'version="1.0"'), "<methodResponse>"]
      encoders = []

      if is_ret
        parts << "<params>"
        params.each do |param|
          parts << "<param>"
          stream_conv2value(parts, encoders, param)
          parts << "</param>"
        end
        parts << "</params>"
      else
        if params.size != 1 or params[0] === XMLRPC::FaultException
          raise ArgumentError, "no valid fault-structure given"
        end
        parts << "<fault>"
        stream_conv2value(parts, encoders, params[0].to_h)
        parts << "</fault>"
      end

      parts << "</methodResponse>\n"
      XMLWriter::StreamingDocument.new(parts, encoders)
    end



    private

    def stream_document(parts, encoders, params)
      if params.empty?
        parts << "<params/></methodCall>\n"
      else
        parts << "<params>"
        params.each do |param|
          parts << "<param>"
          stream_conv2value(parts, encoders, param)
          parts << "</param>"
        end
        parts << "</params>"
      end
      parts << "</methodCall>\n"
      XMLWriter::StreamingDocument.new(parts, encoders)
    end

    def stream_param?(param)
      case param
      when XMLRPC::Base64::Stream
        true
      when Array
        param.any? { |value| stream_param?(value) }
      when Hash
        param.any? { |_key, value| stream_param?(value) }
      when Struct
        param.members.any? { |member| stream_param?(param[member]) }
      else
        readable_param?(param)
      end
    end

    def stream_conv2value(parts, encoders, param)
      case param
      when XMLRPC::Base64::Stream
        encoder = XMLRPC::Base64::StreamEncoder.new(param)
        encoders << encoder
        parts << "<value><base64>" << encoder << "</base64></value>"
      when Array
        parts << "<value><array><data>"
        param.each { |value| stream_conv2value(parts, encoders, value) }
        parts << "</data></array></value>"
      when Hash
        parts << "<value><struct>"
        param.each do |key, value|
          parts << "<member>" << @writer.tag("name", key.to_s)
          stream_conv2value(parts, encoders, value)
          parts << "</member>"
        end
        parts << "</struct></value>"
      when Struct
        parts << "<value><struct>"
        param.members.each do |member|
          parts << "<member>" << @writer.tag("name", member.to_s)
          stream_conv2value(parts, encoders, param[member])
          parts << "</member>"
        end
        parts << "</struct></value>"
      else
        if readable_param?(param)
          stream = XMLRPC::Base64::Stream.new(param)
          encoder = XMLRPC::Base64::StreamEncoder.new(stream)
          encoders << encoder
          parts << "<value><base64>" << encoder << "</base64></value>"
        else
          parts << conv2value(param)
        end
      end
    end

    def readable_param?(param)
      param.respond_to?(:read) && !param.is_a?(XMLRPC::Base64)
    end

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


  end # class Create

end # module XMLRPC
