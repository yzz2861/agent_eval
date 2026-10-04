# encoding: utf-8
# frozen_string_literal: true

module Mail
  # DKIM-Signature field (RFC 6376).
  #
  # Unlike other unstructured fields, the field value is emitted verbatim:
  # the signature is computed over the exact folded form of the header, so
  # re-wrapping the value on output would invalidate it.
  class DkimField < NamedUnstructuredField #:nodoc:
    NAME = 'DKIM-Signature'

    private

    def do_encode
      "#{name}: #{value}\r\n"
    end

    def do_decode
      value
    end
  end
end
