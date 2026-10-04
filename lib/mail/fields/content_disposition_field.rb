# encoding: utf-8
# frozen_string_literal: true

module Mail
  class ContentDispositionField < NamedStructuredField #:nodoc:
    NAME = 'Content-Disposition'

    def self.singular?
      true
    end

    def initialize(value = nil, charset = nil)
      super ensure_filename_quoted(value), charset
    end

    def element
      @element ||= Mail::ContentDispositionElement.new(value)
    end

    def disposition_type
      element.disposition_type
    end

    def parameters
      @parameters = ParameterHash.new
      element.parameters.each { |p| @parameters.merge!(p) } unless element.parameters.nil?
      @parameters
    end

    # Decodes the RFC 2183/RFC 2231 parameters. In lenient mode (the
    # default, identical to #parameters) returns an IndifferentHash. With
    # <tt>strict: true</tt> returns a Mail::ParameterDecodeResult holding
    # the decoded parameters plus structured diagnostics for duplicate or
    # gapped RFC 2231 segments, invalid percent escapes, unsupported
    # charsets and plain/extended parameter conflicts.
    def decoded_parameters(strict: false)
      ParameterDecoder.decode(element.parameters || [], strict: strict, field: NAME)
    end

    def filename
      @filename ||= parameters['filename'] || parameters['name']
    end

    def encoded
      p = ";\r\n\s#{parameters.encoded}" if parameters.length > 0
      "#{name}: #{disposition_type}#{p}\r\n"
    end

    def decoded
      p = "; #{parameters.decoded}" if parameters.length > 0
      "#{disposition_type}#{p}"
    end
  end
end
