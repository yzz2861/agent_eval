# frozen_string_literal: false
#
# Copyright (C) 2001, 2002, 2003 by Michael Neumann (mneumann@ntecs.de)
#
# $Id$
#

require "xmlrpc/parser"
require "xmlrpc/create"
require "xmlrpc/config"
require "xmlrpc/utils"

module XMLRPC # :nodoc:

  # Marshalling of XMLRPC::Create#methodCall and XMLRPC::Create#methodResponse
  class Marshal
    include ParserWriterChooseMixin

    class << self

      def dump_call( methodName, *params )
        new.dump_call( methodName, *params )
      end

      def dump_call_stream( methodName, *params, &block )
        new.dump_call_stream( methodName, *params, &block )
      end

      def dump_response( param )
        new.dump_response( param )
      end

      def dump_response_stream( param, &block )
        new.dump_response_stream( param, &block )
      end

      def load_call( stringOrReadable, base64_sink: nil )
        new.load_call( stringOrReadable, base64_sink: base64_sink )
      end

      def load_response( stringOrReadable, base64_sink: nil )
        new.load_response( stringOrReadable, base64_sink: base64_sink )
      end

      alias dump dump_response
      alias load load_response

    end # class self

    def initialize( parser = nil, writer = nil )
      set_parser( parser )
      set_writer( writer )
    end

    def dump_call( methodName, *params )
      create.methodCall( methodName, *params )
    end

    # Streams a methodCall document (see XMLRPC::Create#methodCall_stream).
    def dump_call_stream( methodName, *params, &block )
      create.methodCall_stream( methodName, *params, &block )
    end

    def dump_response( param )
      create.methodResponse( ! param.kind_of?( XMLRPC::FaultException ) , param )
    end

    # Streams a methodResponse document
    # (see XMLRPC::Create#methodResponse_stream).
    def dump_response_stream( param, &block )
      create.methodResponse_stream( ! param.kind_of?( XMLRPC::FaultException ), param, &block )
    end

    # Returns <code>[ methodname, params ]</code>
    def load_call( stringOrReadable, base64_sink: nil )
      parser.parseMethodCall( stringOrReadable, base64_sink: base64_sink )
    end

    # Returns +paramOrFault+
    def load_response( stringOrReadable, base64_sink: nil )
      parser.parseMethodResponse( stringOrReadable, base64_sink: base64_sink )[1]
    end

  end # class Marshal

end
