# encoding: utf-8
# frozen_string_literal: true
require 'mail/fields/common_field'
require 'mail/fields/unstructured_field'

module Mail
  # A DKIM-Signature header field whose encoded form is emitted
  # verbatim. The field value is computed and signed as a whole by
  # Mail::Dkim, so it must never be refolded or otherwise rewritten on
  # output -- doing so would invalidate the signature under simple
  # header canonicalization.
  class DkimSignatureField < UnstructuredField
    NAME = 'DKIM-Signature'

    # +encoded+ is the complete header field, including the trailing
    # CRLF. +value+ is the unfolded field value (the DKIM tag list).
    def initialize(encoded, value)
      @encoded = encoded
      super(NAME, value, nil)
    end

    private

    def do_encode
      @encoded
    end
  end
end
