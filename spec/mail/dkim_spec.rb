# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'
require 'openssl'

# An independent DKIM (RFC 6376) verifier, written from scratch for this
# spec. It shares no code with Mail::Dkim: it parses the raw message
# text, canonicalizes header and body on its own and performs the RSA
# verification itself, so a bug in the signing code cannot be hidden by
# the verification.
module IndependentDkimVerifier
  CRLF = "\r\n"

  class VerificationError < StandardError; end

  module_function

  # Returns true when the topmost DKIM-Signature in +raw_message+
  # verifies against +public_key+, raises VerificationError otherwise.
  def verify!(raw_message, public_key)
    head, body = raw_message.split("#{CRLF}#{CRLF}", 2)
    raise VerificationError, 'malformed message' unless body

    fields = parse_fields(head)
    sig_index = fields.index { |name, _| name.downcase == 'dkim-signature' }
    raise VerificationError, 'no DKIM-Signature header field' unless sig_index

    sig_name, sig_raw = fields[sig_index]
    tags = parse_tags(sig_raw)

    raise VerificationError, "unsupported algorithm #{tags['a'].inspect}" unless tags['a'] == 'rsa-sha256'
    header_canon, body_canon = (tags['c'] || 'simple/simple').split('/', 2)
    body_canon ||= header_canon

    expected_bh = [Digest::SHA256.digest(canonicalize_body(body, body_canon))].pack('m0')
    raise VerificationError, 'body hash mismatch' unless expected_bh == tags['bh']

    # Only header fields below the DKIM-Signature field are candidates.
    below = fields[(sig_index + 1)..-1] || []
    used = Array.new(below.length, false)
    hash_input = String.new
    tags['h'].to_s.split(':').each do |name|
      index = nil
      (below.length - 1).downto(0) do |i|
        if !used[i] && below[i][0].downcase == name.downcase
          index = i
          break
        end
      end
      next unless index
      used[index] = true
      hash_input << canonicalize_header(*below[index], header_canon) << CRLF
    end

    # The DKIM-Signature field itself is hashed with an empty b= value
    # and no terminating CRLF.
    emptied = sig_raw.sub(/;\s*b=[^;]*/m, '; b=')
    raise VerificationError, 'could not empty the b= tag' if emptied == sig_raw
    hash_input << canonicalize_header(sig_name, emptied, header_canon)

    signature = tags['b'].to_s.gsub(/[^A-Za-z0-9+\/=]/, '').unpack1('m0')
    unless public_key.verify(OpenSSL::Digest::SHA256.new, signature, hash_input)
      raise VerificationError, 'signature does not verify'
    end
    true
  end

  def verify(raw_message, public_key)
    verify!(raw_message, public_key)
  rescue VerificationError
    false
  end

  # Splits the header section into [name, raw_field_text] pairs, keeping
  # folding intact and excluding the terminating CRLF of each field.
  def parse_fields(head)
    fields = []
    head.split(CRLF, -1).each do |line|
      if line =~ /\A[ \t]/ && fields.last
        fields.last[1] << CRLF << line
      else
        name = line.split(':', 2).first
        fields << [name, line]
      end
    end
    fields
  end

  def parse_tags(sig_raw)
    value = sig_raw.split(':', 2).last.gsub(/\r\n[ \t]/, ' ')
    value.split(';').each_with_object({}) do |tag, hash|
      name, tag_value = tag.strip.split('=', 2)
      hash[name.downcase] = tag_value.to_s.strip
    end
  end

  def canonicalize_header(name, raw, type)
    case type
    when 'simple'
      raw
    when 'relaxed'
      field_name, value = raw.split(':', 2)
      field_name = field_name.gsub(/[ \t]+\z/, '')
      unfolded = value.gsub(/\r\n[ \t]/, ' ')
      compressed = unfolded.gsub(/[ \t]+/, ' ').gsub(/\A | \z/, '')
      "#{field_name.downcase}:#{compressed}"
    else
      raise VerificationError, "unknown canonicalization #{type.inspect}"
    end
  end

  def canonicalize_body(body, type)
    case type
    when 'simple'
      body.sub(/(\r\n)*\z/, '') + CRLF
    when 'relaxed'
      lines = body.split(CRLF, -1).map { |line| line.gsub(/[ \t]+/, ' ').sub(/ \z/, '') }
      lines.pop while lines.last == ''
      lines.empty? ? '' : lines.join(CRLF) + CRLF
    else
      raise VerificationError, "unknown canonicalization #{type.inspect}"
    end
  end
end

RSpec.describe Mail::Dkim do
  let(:key) { OpenSSL::PKey::RSA.new(1024) }
  let(:verifier) { IndependentDkimVerifier }

  def build_mail(body_text = "Hello Bob!\nSee you tomorrow.\n")
    Mail.new do
      from    'alice@example.com'
      to      'bob@example.net'
      subject 'DKIM test'
      body    body_text
    end
  end

  def sign(mail, options = {})
    mail.sign_with_dkim({ :domain => 'example.com', :selector => 's1', :private_key => key }.merge(options))
  end

  describe 'signing and verification' do
    it 'signs with relaxed/relaxed by default and the signature verifies' do
      mail = build_mail
      sign(mail)
      expect(verifier.verify!(mail.encoded, key.public_key)).to eq(true)
    end

    %w[simple/simple relaxed/relaxed simple/relaxed relaxed/simple].each do |canon|
      it "signs and verifies with #{canon} canonicalization" do
        mail = build_mail
        sign(mail, :canonicalization => canon)
        expect(mail['DKIM-Signature'].value).to include("c=#{canon}")
        expect(verifier.verify!(mail.encoded, key.public_key)).to eq(true)
      end
    end

    it 'rejects an unknown canonicalization' do
      mail = build_mail
      expect { sign(mail, :canonicalization => 'funky/simple') }.to raise_error(ArgumentError)
    end

    it 'prepends the DKIM-Signature header field' do
      mail = build_mail
      sign(mail)
      expect(mail.header.fields.first).to be_a(Mail::DkimSignatureField)
      expect(mail.encoded).to start_with('DKIM-Signature: ')
    end

    it 'includes the required tags' do
      mail = build_mail
      sign(mail, :time => Time.at(1_700_000_000), :identity => 'alice@example.com')
      value = mail['DKIM-Signature'].value
      expect(value).to include('v=1')
      expect(value).to include('a=rsa-sha256')
      expect(value).to include('d=example.com')
      expect(value).to include('s=s1')
      expect(value).to include('i=alice@example.com')
      expect(value).to include('t=1700000000')
      expect(value).to match(/bh=[A-Za-z0-9+\/=]+/)
      expect(value).to include('h=')
    end

    it 'accepts a PEM encoded private key' do
      mail = build_mail
      sign(mail, :private_key => key.to_pem)
      expect(verifier.verify!(mail.encoded, key.public_key)).to eq(true)
    end

    it 'signs every occurrence of repeated header fields' do
      mail = build_mail
      mail['X-Trace'] = 'first'
      mail['X-Trace'] = 'second'
      sign(mail, :headers => %w[from x-trace x-trace])
      value = mail['DKIM-Signature'].value
      expect(value).to include('h=from:x-trace:x-trace')
      expect(verifier.verify!(mail.encoded, key.public_key)).to eq(true)
    end

    it 'signs all header fields with :headers => :all' do
      mail = build_mail
      mail['X-Custom'] = 'yes'
      sign(mail, :headers => :all)
      expect(mail['DKIM-Signature'].value).to include('x-custom')
      expect(verifier.verify!(mail.encoded, key.public_key)).to eq(true)
    end

    it 'never includes dkim-signature in the h= tag' do
      mail = build_mail
      sign(mail)
      sign(mail)
      value = mail.header.fields.first.value
      expect(value).not_to include('dkim-signature:')
      expect(verifier.verify!(mail.encoded, key.public_key)).to eq(true)
    end

    it 'verifies a multipart/alternative message' do
      mail = Mail.new do
        from    'alice@example.com'
        to      'bob@example.net'
        subject 'multipart'
        text_part { body 'plain text' }
        html_part { content_type 'text/html; charset=UTF-8'; body '<p>html</p>' }
      end
      sign(mail)
      expect(verifier.verify!(mail.encoded, key.public_key)).to eq(true)
    end

    it 'verifies a message with an empty body' do
      mail = build_mail('')
      sign(mail, :canonicalization => 'simple/simple')
      expect(verifier.verify!(mail.encoded, key.public_key)).to eq(true)

      mail = build_mail('')
      sign(mail, :canonicalization => 'relaxed/relaxed')
      expect(verifier.verify!(mail.encoded, key.public_key)).to eq(true)
    end

    it 'verifies a body with trailing blank and whitespace-only lines' do
      mail = build_mail("content\r\n \t \r\n\r\n")
      sign(mail, :canonicalization => 'relaxed/relaxed')
      expect(verifier.verify!(mail.encoded, key.public_key)).to eq(true)

      mail = build_mail("content\r\n \t \r\n\r\n")
      sign(mail, :canonicalization => 'simple/simple')
      expect(verifier.verify!(mail.encoded, key.public_key)).to eq(true)
    end
  end

  describe 'transfer encoding and output stability' do
    it 'finalizes the transfer encoding before signing' do
      mail = build_mail("Grüße aus Köln\n")
      mail.charset = 'UTF-8'
      sign(mail)
      expect(mail.content_transfer_encoding).not_to be_nil
      expect(mail.content_transfer_encoding.to_s).not_to eq('7bit')
      expect(verifier.verify!(mail.encoded, key.public_key)).to eq(true)
    end

    it 'does not change the signed bytes on subsequent output' do
      mail = build_mail("Grüße aus Köln\n")
      mail.charset = 'UTF-8'
      before = mail.encoded
      sign(mail)
      after = mail.encoded
      # Everything but the prepended DKIM-Signature field is identical.
      expect(after.sub(/\ADKIM-Signature:.*?\r\n(?=[A-Za-z-]+:)/m, '')).to eq(before)
    end

    it 'produces identical output on repeated calls after signing' do
      mail = build_mail
      sign(mail)
      expect(mail.encoded).to eq(mail.encoded)
      expect(mail.to_s).to eq(mail.encoded)
    end

    it 'still verifies after repeated encoding' do
      mail = build_mail
      sign(mail)
      mail.encoded
      mail.to_s
      expect(verifier.verify!(mail.encoded, key.public_key)).to eq(true)
    end
  end

  describe 'tamper detection' do
    it 'fails verification when the body is changed after signing' do
      mail = build_mail
      sign(mail)
      mail.body = 'forged body'
      expect(verifier.verify(mail.encoded, key.public_key)).to eq(false)
    end

    it 'fails verification when a signed header is changed after signing' do
      mail = build_mail
      sign(mail)
      mail.subject = 'forged subject'
      expect(verifier.verify(mail.encoded, key.public_key)).to eq(false)
    end

    it 'fails verification when a signed header occurrence is added' do
      mail = build_mail
      mail['X-Trace'] = 'first'
      sign(mail, :headers => %w[from x-trace])
      mail['X-Trace'] = 'injected'
      expect(verifier.verify(mail.encoded, key.public_key)).to eq(false)
    end

    it 'fails verification with a different key' do
      mail = build_mail
      sign(mail)
      other = OpenSSL::PKey::RSA.new(1024)
      expect(verifier.verify(mail.encoded, other.public_key)).to eq(false)
    end
  end

  describe 'empty b= handling' do
    it 'emits the signature value on continuation lines after b=' do
      mail = build_mail
      sign(mail)
      field = mail.header.fields.first
      expect(field.encoded).to match(/b=\r\n [A-Za-z0-9+\/=]+\r\n/)
    end

    it 'hashes the DKIM-Signature header with an empty b= value' do
      mail = build_mail
      sign(mail, :canonicalization => 'simple/simple')
      field = mail.header.fields.first
      # The verifier independently strips the b= value; verification
      # only succeeds if the signer hashed the empty-b= form.
      expect(verifier.verify!(mail.encoded, key.public_key)).to eq(true)
      expect(field.encoded).to include('; b=')
    end
  end

  describe 'canonicalization known answers (RFC 6376 3.4)' do
    FakeField = Struct.new(:encoded)

    it 'canonicalizes headers with the simple algorithm unchanged' do
      field = FakeField.new("X-A:  spaced \t value\r\n")
      expect(Mail::Dkim.canonicalize_header_field(field, 'simple')).to eq("X-A:  spaced \t value\r\n")
    end

    it 'canonicalizes headers with the relaxed algorithm' do
      field = FakeField.new("B : Y\r\n\tZ  \r\n")
      expect(Mail::Dkim.canonicalize_header_field(field, 'relaxed')).to eq("b:Y Z\r\n")
    end

    it 'canonicalizes the body with the simple algorithm' do
      expect(Mail::Dkim.canonicalize_body("abc\r\n\r\n\r\n", 'simple')).to eq("abc\r\n")
      expect(Mail::Dkim.canonicalize_body('', 'simple')).to eq("\r\n")
      expect(Mail::Dkim.canonicalize_body("abc", 'simple')).to eq("abc\r\n")
    end

    it 'canonicalizes the body with the relaxed algorithm' do
      expect(Mail::Dkim.canonicalize_body("a \t b\t\r\n \r\n\r\n", 'relaxed')).to eq("a b\r\n")
      expect(Mail::Dkim.canonicalize_body('', 'relaxed')).to eq('')
      expect(Mail::Dkim.canonicalize_body("\r\n\r\n", 'relaxed')).to eq('')
    end

    it 'normalizes bare LF line endings to CRLF before hashing' do
      expect(Mail::Dkim.canonicalize_body("a\nb\n", 'simple')).to eq("a\r\nb\r\n")
    end
  end
end
