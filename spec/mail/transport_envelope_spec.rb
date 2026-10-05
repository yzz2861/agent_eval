# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::TransportEnvelope do
  def build_mail(&block)
    Mail.new do
      from    'sender@example.com'
      to      'recipient@example.net'
      subject 'Hello'
      instance_eval(&block) if block
    end
  end

  def signed_mail(part_encoding, part_body)
    mail = build_mail do
      content_type 'multipart/signed; protocol="application/pgp-signature"'
    end
    mail.add_part Mail::Part.new(content_type: 'text/plain; charset=UTF-8',
                                 content_transfer_encoding: part_encoding,
                                 body: part_body)
    mail.add_part Mail::Part.new(content_type: 'application/pgp-signature',
                                 body: 'signature-data')
    mail
  end

  describe 'preparing for a 7bit-only transport' do
    it 'keeps 7bit content as-is and requires no extensions' do
      mail = build_mail { body 'plain ascii body' }
      envelope = mail.prepare_for_transport

      expect(envelope.requirements).to eq []
      expect(envelope.message).to include 'Content-Transfer-Encoding: 7bit'
      expect(envelope.message).to be_ascii_only
    end

    it 'rewrites 8bit content to a 7bit-safe encoding' do
      mail = build_mail do
        content_type 'text/plain; charset=UTF-8'
        body 'a café on every corner of the street, café after café'
      end
      envelope = mail.prepare_for_transport

      expect(envelope.requirements).to eq []
      expect(envelope.message).to be_ascii_only
      expect(envelope.message).to include 'Content-Transfer-Encoding: quoted-printable'
      expect(envelope.message).to include 'caf=C3=A9'
    end

    it 'encodes binary content as base64' do
      mail = build_mail do
        content_type 'application/octet-stream'
        body "\x00\xFF\x00\xFF".b
      end
      envelope = mail.prepare_for_transport

      expect(envelope.requirements).to eq []
      expect(envelope.message).to be_ascii_only
      expect(envelope.message).to include 'Content-Transfer-Encoding: base64'
    end

    it 'encodes internationalized header fields as ASCII encoded-words' do
      mail = build_mail { subject 'Grüße 你好' }
      envelope = mail.prepare_for_transport

      expect(envelope.requirements).to eq []
      expect(envelope.message).to be_ascii_only
      expect(envelope.message).to match(/Subject: =\?UTF-8\?[BQ]\?/)
    end

    it 'pushes the constraint down to nested MIME parts' do
      mail = build_mail do
        text_part { body 'a tëxt part with plenty of plain ascii text' }
        html_part { body '<b>html</b>' }
      end
      envelope = mail.prepare_for_transport

      expect(envelope.requirements).to eq []
      expect(envelope.message).to be_ascii_only
      expect(envelope.message).to include 't=C3=ABxt'
    end
  end

  describe 'preparing for an 8BITMIME transport' do
    it 'keeps 8bit content as 8bit and reports the requirement' do
      mail = build_mail do
        content_type 'text/plain; charset=UTF-8'
        body 'café'
      end
      envelope = mail.prepare_for_transport(eight_bit_mime: true)

      expect(envelope.requirements).to eq ['8BITMIME']
      expect(envelope).to be_requires_8bitmime
      expect(envelope).not_to be_requires_smtputf8
      expect(envelope).not_to be_requires_binarymime
      expect(envelope.message).to include 'Content-Transfer-Encoding: 8bit'
      expect(envelope.message).to include 'café'
    end

    it 'detects the requirement from nested parts, not just the top-level body' do
      mail = build_mail do
        text_part { body 'ascii text' }
        html_part { body '<b>café</b>' }
      end
      envelope = mail.prepare_for_transport(eight_bit_mime: true)

      expect(envelope.requirements).to eq ['8BITMIME']
    end

    it 'still encodes binary content for transport' do
      mail = build_mail do
        content_type 'application/octet-stream'
        body "\xFF".b * 2000
      end
      envelope = mail.prepare_for_transport(eight_bit_mime: true)

      expect(envelope.requirements).to eq []
      expect(envelope.message).to be_ascii_only
      expect(envelope.message).to include 'Content-Transfer-Encoding: base64'
    end
  end

  describe 'preparing for a BINARYMIME transport' do
    it 'keeps binary content as binary and reports the requirement' do
      mail = build_mail do
        content_type 'application/octet-stream'
        content_transfer_encoding 'binary'
        body "\x00\xFF\x00\xFF".b
      end
      envelope = mail.prepare_for_transport(binary_mime: true)

      expect(envelope.requirements).to eq ['BINARYMIME']
      expect(envelope).to be_requires_binarymime
      expect(envelope.message).to include 'Content-Transfer-Encoding: binary'
    end
  end

  describe 'SMTPUTF8 envelope addresses' do
    it 'refuses non-ASCII envelope addresses without SMTPUTF8' do
      mail = build_mail { from '用户@example.com' }

      expect { mail.prepare_for_transport }.to raise_error(Mail::TransportError, /SMTPUTF8/)
    end

    it 'requires SMTPUTF8 for non-ASCII envelope addresses' do
      mail = build_mail { from '用户@example.com' }
      envelope = mail.prepare_for_transport(smtputf8: true)

      expect(envelope.requirements).to eq ['SMTPUTF8']
      expect(envelope).to be_requires_smtputf8
      expect(envelope.from).to eq '用户@example.com'
    end

    it 'requires SMTPUTF8 for non-ASCII recipients' do
      mail = build_mail { to 'recipient@example.net, 用户@example.com' }

      expect { mail.prepare_for_transport }.to raise_error(Mail::TransportError)
      envelope = mail.prepare_for_transport(smtputf8: true)
      expect(envelope.requirements).to eq ['SMTPUTF8']
      expect(envelope.to).to include '用户@example.com'
    end
  end

  describe 'signed subtrees' do
    it 'refuses to prepare when signed content is incompatible with the transport' do
      mail = signed_mail('8bit', 'signed café')

      expect { mail.prepare_for_transport }.to raise_error(Mail::TransportError, /signed content/)
    end

    it 'refuses signed content with non-ASCII header fields' do
      mail = signed_mail('7bit', 'signed text')
      mail.parts.first.subject 'Grüße'

      expect { mail.prepare_for_transport }.to raise_error(Mail::TransportError, /header/)
    end

    it 'transports compatible signed content without rewriting it' do
      mail = signed_mail('base64', "c2lnbmVkIGNhZsOp\n")
      envelope = mail.prepare_for_transport

      expect(envelope.requirements).to eq []
      expect(envelope.message).to include 'c2lnbmVkIGNhZsOp'
      expect(envelope.message).to include 'Content-Transfer-Encoding: base64'
    end

    it 'keeps 8bit signed content on an 8BITMIME transport' do
      mail = signed_mail('8bit', 'signed café')
      envelope = mail.prepare_for_transport(eight_bit_mime: true)

      expect(envelope.requirements).to eq ['8BITMIME']
      expect(envelope.message).to include 'signed café'
    end
  end

  describe 'encapsulated messages' do
    it 'refuses a message/rfc822 part that cannot be transported within its allowed encodings' do
      mail = build_mail do
        content_type 'message/rfc822'
        content_transfer_encoding 'binary'
        body "From: a@b.net\r\n\r\n" + ('x' * 2000)
      end

      expect { mail.prepare_for_transport(eight_bit_mime: true) }.to raise_error(Mail::TransportError, /message\/rfc822/)
    end

    it 'transports a message/rfc822 part when a compatible encoding exists' do
      mail = build_mail do
        content_type 'message/rfc822'
        content_transfer_encoding 'binary'
        body "From: a@b.net\r\n\r\n" + ('x' * 2000)
      end
      envelope = mail.prepare_for_transport(binary_mime: true)

      expect(envelope.requirements).to eq ['BINARYMIME']
    end
  end

  describe 'envelope attributes' do
    it 'exposes the envelope sender and recipients' do
      mail = build_mail { body 'hi' }
      envelope = mail.prepare_for_transport

      expect(envelope.from).to eq 'sender@example.com'
      expect(envelope.to).to eq ['recipient@example.net']
    end

    it 'matches capabilities by name case-insensitively' do
      mail = build_mail do
        content_type 'text/plain; charset=UTF-8'
        body 'café'
      end
      envelope = mail.prepare_for_transport(eight_bit_mime: true)

      expect(envelope.requires?('8bitmime')).to be true
      expect(envelope.requires?('SMTPUTF8')).to be false
    end
  end

  describe 'original message preservation' do
    it 'does not modify the original message on success' do
      mail = build_mail do
        content_type 'text/plain; charset=UTF-8'
        body 'café'
      end
      mail.prepare_for_transport(eight_bit_mime: true)

      expect(mail.content_transfer_encoding).to be_nil
      expect(mail.message_id).to be_nil
      expect(mail.date).to be_nil
      expect(mail.body.encoding).to eq '8bit'
    end

    it 'does not modify the original message when preparation fails' do
      mail = signed_mail('8bit', 'signed café')

      expect { mail.prepare_for_transport }.to raise_error(Mail::TransportError)

      expect(mail.parts.first.content_transfer_encoding).to eq '8bit'
      expect(mail.parts.first.body.raw_source).to eq 'signed café'
      expect(mail.message_id).to be_nil
      expect(mail.date).to be_nil
    end

    it 'does not share nested parts with the prepared copy' do
      mail = build_mail do
        text_part { body 'tëxt' }
        html_part { body '<b>café</b>' }
      end
      envelope = mail.prepare_for_transport

      expect(envelope.message).to be_ascii_only
      expect(mail.parts.map { |part| part.content_transfer_encoding }).to eq [nil, nil]
      expect(mail.html_part.body.raw_source).to eq '<b>café</b>'
    end
  end
end
