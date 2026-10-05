# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::TransportPreparation do
  def build_mail(body = 'hello world')
    Mail.new do
      from    'sender@example.com'
      to      'rcpt@example.com'
      subject 'A test'
      body    body
    end
  end

  describe 'a plain ASCII message' do
    it 'returns a PreparedMessage with no required extensions' do
      prepared = build_mail.prepare_for_transport
      expect(prepared).to be_a(Mail::PreparedMessage)
      expect(prepared.required_extensions).to eq []
      expect(prepared.body_type).to eq '7BIT'
      expect(prepared.smtputf8?).to eq false
      expect(prepared.from).to eq 'sender@example.com'
      expect(prepared.to).to eq ['rcpt@example.com']
      expect(prepared.message).to be_ascii_only
    end

    it 'is also available through Mail::SmtpEnvelope.prepare' do
      prepared = Mail::SmtpEnvelope.prepare(build_mail)
      expect(prepared).to be_a(Mail::PreparedMessage)
      expect(prepared.message).to be_ascii_only
    end
  end

  describe '8-bit bodies without 8BITMIME' do
    it 'downgrades the rewritable body to quoted-printable' do
      mail = build_mail(('plain ascii text ' * 30) + "with one \u00e9 acc\u00e9nt")
      prepared = mail.prepare_for_transport
      expect(prepared.required_extensions).to eq []
      expect(prepared.message).to include('Content-Transfer-Encoding: quoted-printable')
      expect(prepared.message).to be_ascii_only
      expect(mail.content_transfer_encoding).to be_nil
    end

    it 'negotiates independently on every nested MIME part' do
      mail = Mail.new
      mail.from = 'sender@example.com'
      mail.to = 'rcpt@example.com'
      mail.text_part = Mail::Part.new(:content_type => 'text/plain; charset=UTF-8') { body "h\u00e9llo" }
      mail.html_part = Mail::Part.new(:content_type => 'text/html; charset=UTF-8') { body "<p>h\u00e9llo</p>" }

      prepared = mail.prepare_for_transport
      expect(prepared.required_extensions).to eq []
      expect(prepared.message).to be_ascii_only
      expect(prepared.message).to include('Content-Transfer-Encoding: quoted-printable')
      expect(prepared.message).not_to include('Content-Transfer-Encoding: 8bit')
    end
  end

  describe 'with 8BITMIME' do
    it 'keeps the 8-bit body and reports 8BITMIME as required' do
      prepared = build_mail("h\u00e9llo").prepare_for_transport(:eightbitmime => true)
      expect(prepared.required_extensions).to eq ['8BITMIME']
      expect(prepared.body_type).to eq '8BIT-MIME'
      expect(prepared.message).to include('Content-Transfer-Encoding: 8bit')
    end

    it 'accepts canonical EHLO keyword strings' do
      prepared = build_mail("h\u00e9llo").prepare_for_transport('8BITMIME' => [])
      expect(prepared.required_extensions).to eq ['8BITMIME']
    end
  end

  describe 'with BINARYMIME' do
    it 'implies 8BITMIME and carries binary content untouched' do
      mail = build_mail
      mail.attachments['blob.bin'] = {
        :mime_type => 'application/octet-stream',
        :content => "\x00\x01\n" * 1000
      }

      prepared = mail.prepare_for_transport(:binarymime => true)
      expect(prepared.required_extensions).to include 'BINARYMIME', '8BITMIME'
      expect(prepared.body_type).to eq 'BINARYMIME'
      expect(prepared.message).to include('Content-Transfer-Encoding: binary')
    end

    it 'falls back to a 7-bit safe encoding without BINARYMIME' do
      mail = build_mail
      mail.attachments['blob.bin'] = {
        :mime_type => 'application/octet-stream',
        :content => "\x00\x01\n" * 100
      }

      prepared = mail.prepare_for_transport
      expect(prepared.required_extensions).to eq []
      expect(prepared.message).to include('Content-Transfer-Encoding: base64')
      expect(prepared.message).to be_ascii_only
    end
  end
end

RSpec.describe Mail::TransportPreparation, 'SMTPUTF8' do
  def build_mail
    Mail.new do
      from 'sender@example.com'
      to 'rcpt@example.com'
      subject 'A test'
      body 'hello'
    end
  end

  it 'passes an internationalized envelope From through unchanged' do
    mail = build_mail
    mail.smtp_envelope_from = "t\u00e9st@example.com"
    prepared = mail.prepare_for_transport(:smtputf8 => true)
    expect(prepared.required_extensions).to eq ['SMTPUTF8']
    expect(prepared.from).to eq "t\u00e9st@example.com"
    expect(prepared.smtputf8?).to eq true
  end

  it 'is required for an internationalized envelope To' do
    mail = build_mail
    mail.smtp_envelope_to = ["t\u00e9st@example.com"]
    prepared = mail.prepare_for_transport(:smtputf8 => true)
    expect(prepared.required_extensions).to eq ['SMTPUTF8']
  end

  it 'rejects an internationalized envelope address without SMTPUTF8' do
    mail = build_mail
    mail.smtp_envelope_from = "t\u00e9st@example.com"
    expect { mail.prepare_for_transport }.to raise_error(
      Mail::IncompatibleTransportError, /SMTPUTF8/
    )
  end

  it 'rejects an internationalized header addr-spec without SMTPUTF8' do
    mail = Mail.new do
      from "t\u00e9st@example.com"
      to 'rcpt@example.com'
      body 'x'
    end
    expect { mail.prepare_for_transport }.to raise_error(
      Mail::IncompatibleTransportError, /SMTPUTF8/
    )
  end

  it 'accepts internationalized addresses when SMTPUTF8 is offered' do
    mail = Mail.new do
      from "t\u00e9st@example.com"
      to 'rcpt@example.com'
      body 'x'
    end
    prepared = mail.prepare_for_transport(:smtputf8 => true)
    expect(prepared.required_extensions).to include 'SMTPUTF8'
  end

  it 'does not require SMTPUTF8 for an RFC 2047 encoded-word subject' do
    mail = build_mail
    mail.subject = "h\u00e9llo"
    prepared = mail.prepare_for_transport
    expect(prepared.required_extensions).to eq []
    expect(prepared.message).to be_ascii_only
  end
end

RSpec.describe Mail::TransportPreparation, 'signed subtrees and nested entities' do
  let(:signed_source) do
    "From: sender@example.com\r\n" \
    "To: rcpt@example.com\r\n" \
    "Subject: signed\r\n" \
    "MIME-Version: 1.0\r\n" \
    "Content-Type: multipart/signed; protocol=\"application/pgp-signature\";\r\n" \
    " boundary=\"BOUND\"\r\n" \
    "\r\n" \
    "--BOUND\r\n" \
    "Content-Type: text/plain; charset=UTF-8\r\n" \
    "Content-Transfer-Encoding: 8bit\r\n" \
    "\r\n" \
    "h\u00e9llo signed\r\n" \
    "--BOUND\r\n" \
    "Content-Type: application/pgp-signature\r\n" \
    "Content-Transfer-Encoding: 7bit\r\n" \
    "\r\n" \
    "FAKESIGDATA\r\n" \
    "--BOUND--\r\n"
  end

  it 'refuses to downgrade a signed 8-bit part without 8BITMIME' do
    expect { Mail.new(signed_source).prepare_for_transport }.to raise_error(
      Mail::IncompatibleTransportError, /8BITMIME/
    )
  end

  it 'carries a signed 8-bit part unchanged with 8BITMIME' do
    prepared = Mail.new(signed_source).prepare_for_transport(:eightbitmime => true)
    expect(prepared.required_extensions).to eq ['8BITMIME']
    expect(prepared.message).to include("h\u00e9llo signed")
    expect(prepared.message).to include('Content-Transfer-Encoding: 8bit')
    expect(prepared.message).not_to include('Content-Transfer-Encoding: quoted-printable')
  end

  it 'rejects a signed part whose bytes do not match its declared encoding' do
    source = signed_source.sub('Content-Transfer-Encoding: 8bit',
                               'Content-Transfer-Encoding: 7bit')
    expect { Mail.new(source).prepare_for_transport }.to raise_error(
      Mail::IncompatibleTransportError, /incompatible/i
    )
  end

  it 'rejects a message/global part without SMTPUTF8' do
    mail = Mail.new do
      from 'sender@example.com'
      to 'rcpt@example.com'
    end
    part = Mail::Part.new(:content_type => 'message/global; charset=UTF-8')
    part.body = "To: t\u00e9st@example.com\r\n\r\nh\u00e9llo"
    mail.add_part(part)
    expect { mail.prepare_for_transport }.to raise_error(
      Mail::IncompatibleTransportError, /SMTPUTF8/
    )
  end

  it 'does not mutate the source message on a rejected preparation' do
    mail = Mail.new(signed_source)
    cte_before = mail.parts.map { |part| part.content_transfer_encoding }
    locked_before = mail.parts.map { |part| part.transport_locked? }
    expect { mail.prepare_for_transport }.to raise_error(Mail::IncompatibleTransportError)
    expect(mail.parts.map { |part| part.content_transfer_encoding }).to eq cte_before
    expect(mail.parts.map { |part| part.transport_locked? }).to eq locked_before
  end

  it 'does not mutate the source message on success' do
    mail = Mail.new do
      from 'sender@example.com'
      to 'rcpt@example.com'
    end
    mail.text_part = Mail::Part.new(:content_type => 'text/plain; charset=UTF-8') { body "h\u00e9llo" }
    mail.html_part = Mail::Part.new(:content_type => 'text/html; charset=UTF-8') { body "<p>h\u00e9llo</p>" }

    mail.prepare_for_transport
    expect(mail.parts.map { |part| part.content_transfer_encoding }).to all(be_nil)
  end

  it 'deep-duplicates nested parts independently' do
    mail = Mail.new
    mail.to = 'rcpt@example.com'
    mail.text_part = Mail::Part.new(:content_type => 'text/plain') { body 'x' }
    copy = mail.deep_dup
    expect(copy.text_part).not_to be_nil
    expect(copy.text_part.object_id).not_to eq mail.text_part.object_id
    copy.text_part.content_transfer_encoding = 'base64'
    expect(mail.parts.first.content_transfer_encoding).not_to eq 'base64'
  end

  it 'rejects an 8-bit message/rfc822 part on a 7-bit-only server' do
    inner = "From: a@example.com\r\nTo: b@example.com\r\n\r\nh\u00e9llo\r\n"
    mail = Mail.new do
      from 'sender@example.com'
      to 'rcpt@example.com'
    end
    attachment = Mail::Part.new(:content_type => 'message/rfc822',
                                 :content_transfer_encoding => '8bit',
                                 :body => inner)
    mail.add_part(attachment)

    expect { mail.prepare_for_transport }.to raise_error(
      Mail::IncompatibleTransportError, /message\/rfc822/
    )
  end

  it 'carries an 8-bit message/rfc822 part with 8BITMIME' do
    inner = "From: a@example.com\r\nTo: b@example.com\r\n\r\nh\u00e9llo\r\n"
    mail = Mail.new do
      from 'sender@example.com'
      to 'rcpt@example.com'
    end
    attachment = Mail::Part.new(:content_type => 'message/rfc822',
                                 :content_transfer_encoding => '8bit',
                                 :body => inner)
    mail.add_part(attachment)

    prepared = mail.prepare_for_transport(:eightbitmime => true)
    expect(prepared.required_extensions).to eq ['8BITMIME']
  end

  it 'protects signed parts nested inside other multipart containers' do
    source = [
      'From: sender@example.com',
      'To: rcpt@example.com',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="OUT"',
      '',
      '--OUT',
      'Content-Type: multipart/signed; protocol="application/pgp-signature"; boundary="IN"',
      '',
      '--IN',
      'Content-Type: text/plain; charset=UTF-8',
      'Content-Transfer-Encoding: 8bit',
      '',
      "signed h\u00e9llo",
      '--IN',
      'Content-Type: application/pgp-signature',
      'Content-Transfer-Encoding: 7bit',
      '',
      'SIGDATA',
      '--IN--',
      '--OUT',
      'Content-Type: text/plain; charset=UTF-8',
      '',
      'unsigned plain',
      '--OUT--',
      ''
    ].join("\r\n")

    expect { Mail.new(source).prepare_for_transport }.to raise_error(
      Mail::IncompatibleTransportError, /8BITMIME/
    )
    prepared = Mail.new(source).prepare_for_transport(:eightbitmime => true)
    expect(prepared.required_extensions).to eq ['8BITMIME']
    expect(prepared.message).to include("signed h\u00e9llo")
  end
end
