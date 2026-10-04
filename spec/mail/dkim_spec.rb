# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::Dkim do
  let(:private_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:public_key)  { private_key.public_key }

  # Independent DKIM verifier: parses the raw message and recomputes the
  # body and header hashes from scratch with its own canonicalization
  # code, then RSA-verifies the signature. Shares no code with the signer.
  def parse_raw_headers(raw)
    header_block, body = raw.split("\r\n\r\n", 2)
    headers = []
    header_block.split("\r\n").each do |line|
      if line =~ /\A[ \t]/
        headers.last[:raw] << "\r\n" << line
      else
        name, value = line.split(":", 2)
        headers << { :name => name, :value => value, :raw => line }
      end
    end
    [headers, body]
  end

  def parse_tag_list(value)
    value.gsub(/\r\n(?=[ \t])/, "").split(";").each_with_object({}) do |tag, tags|
      key, val = tag.strip.split("=", 2)
      tags[key.strip] = val.to_s.strip
    end
  end

  def parse_tags(sig_raw)
    parse_tag_list(sig_raw.split(":", 2)[1])
  end

  def verify_canonicalize_header(raw_with_crlf, method)
    return raw_with_crlf if method == :simple
    name, value = raw_with_crlf.sub(/\r\n\z/, "").split(":", 2)
    value = value.gsub(/\r\n[ \t]/, " ").gsub(/[ \t]+/, " ").strip
    "#{name.downcase}:#{value}\r\n"
  end

  def verify_canonicalize_body(body, method)
    lines = body.split("\r\n", -1)
    lines.pop if lines.last == ""
    if method == :relaxed
      lines = lines.map { |line| line.gsub(/[ \t]+/, " ").sub(/ +\z/, "") }
    end
    lines.pop while lines.last == ""
    lines.empty? ? "" : lines.join("\r\n") + "\r\n"
  end

  def dkim_verify(raw, key, sig_number = 0)
    headers, body = parse_raw_headers(raw)
    sig_indexes = headers.each_index.select { |i| headers[i][:name].downcase == "dkim-signature" }
    sig_index = sig_indexes[sig_number]
    return false unless sig_index
    sig_raw = headers[sig_index][:raw]
    tags = parse_tags(sig_raw)
    header_canon, body_canon = (tags["c"] || "simple/simple").split("/").map(&:to_sym)

    canon_body = verify_canonicalize_body(body, body_canon)
    bh = [OpenSSL::Digest::SHA256.digest(canon_body)].pack("m0")
    return false unless bh == tags["bh"]

    used = []
    hash_input = "".b
    tags["h"].split(":").each do |name|
      name = name.strip.downcase
      index = headers.each_index.reverse_each.find do |i|
        !used.include?(i) && headers[i][:name].downcase == name
      end
      next unless index
      used << index
      hash_input << verify_canonicalize_header(headers[index][:raw] + "\r\n", header_canon)
    end

    # Hash the DKIM-Signature header itself with an empty b= value.
    b_match = sig_raw.match(/b=(?=[^;]*\z)/)
    unsigned_sig = sig_raw[0...(b_match.begin(0) + 2)]
    hash_input << verify_canonicalize_header(unsigned_sig + "\r\n", header_canon)

    signature = tags["b"].gsub(/\s/, "").unpack1("m0")
    key.verify(OpenSSL::Digest::SHA256.new, signature, hash_input)
  end

  def dkim_tags(message)
    parse_tag_list(message["dkim-signature"].field.value)
  end

  def build_message
    Mail.new do
      from    "alice@example.com"
      to      "bob@example.net"
      subject "hello there"
      body    "signed, sealed, delivered"
    end
  end

  def sign(message, options = {})
    message.dkim_sign({
      :domain => "example.com",
      :selector => "s1",
      :private_key => private_key,
      :time => 1_700_000_000
    }.merge(options))
  end

  describe "canonicalization" do
    it "canonicalizes headers with the simple algorithm unchanged" do
      field = "X-Test:  some \t value\r\n\tfolded\r\n"
      expect(Mail::Dkim.canonicalize_header(field, :simple)).to eq field
    end

    it "canonicalizes headers with the relaxed algorithm per RFC 6376 3.4.2" do
      expect(Mail::Dkim.canonicalize_header("A: X\r\n", :relaxed)).to eq "a:X\r\n"
      expect(Mail::Dkim.canonicalize_header("B: Y\t\r\n\tZ \r\n", :relaxed)).to eq "b:Y Z\r\n"
    end

    it "canonicalizes bodies with the simple algorithm per RFC 6376 3.4.3" do
      expect(Mail::Dkim.canonicalize_body("Hello world!\r\n", :simple)).to eq "Hello world!\r\n"
      expect(Mail::Dkim.canonicalize_body("a\r\n\r\n\r\n", :simple)).to eq "a\r\n"
      expect(Mail::Dkim.canonicalize_body("a", :simple)).to eq "a\r\n"
      expect(Mail::Dkim.canonicalize_body("", :simple)).to eq ""
      expect(Mail::Dkim.canonicalize_body("\r\n\r\n", :simple)).to eq ""
    end

    it "canonicalizes bodies with the relaxed algorithm per RFC 6376 3.4.4" do
      expect(Mail::Dkim.canonicalize_body(" C \r\nD \t E\r\n\r\n\r\n", :relaxed)).to eq " C\r\nD E\r\n"
      expect(Mail::Dkim.canonicalize_body("a  b", :relaxed)).to eq "a b\r\n"
      expect(Mail::Dkim.canonicalize_body("", :relaxed)).to eq ""
    end

    it "rejects unknown canonicalization algorithms" do
      expect {
        build_message.dkim_sign(:domain => "d", :selector => "s", :private_key => private_key, :canonicalization => :bogus)
      }.to raise_error(ArgumentError)
    end
  end

  describe "signing" do
    it "requires domain, selector and private_key" do
      expect { build_message.dkim_sign(:selector => "s", :private_key => private_key) }.to raise_error(ArgumentError)
      expect { build_message.dkim_sign(:domain => "d", :private_key => private_key) }.to raise_error(ArgumentError)
      expect { build_message.dkim_sign(:domain => "d", :selector => "s") }.to raise_error(ArgumentError)
    end

    it "prepends a DKIM-Signature header with the expected tags" do
      message = sign(build_message)
      expect(message.encoded).to start_with "DKIM-Signature: "
      tags = dkim_tags(message)
      expect(tags["v"]).to eq "1"
      expect(tags["a"]).to eq "rsa-sha256"
      expect(tags["c"]).to eq "relaxed/relaxed"
      expect(tags["d"]).to eq "example.com"
      expect(tags["s"]).to eq "s1"
      expect(tags["t"]).to eq "1700000000"
      expect(tags["h"].split(":")).to include("from", "to", "subject", "date", "message-id")
      expect(tags["bh"]).not_to be_empty
      expect(tags["b"]).not_to be_empty
    end

    it "verifies with an independent verifier for all canonicalization combinations" do
      %i[simple relaxed].each do |header_canon|
        %i[simple relaxed].each do |body_canon|
          message = sign(build_message, :header_canonicalization => header_canon, :body_canonicalization => body_canon)
          expect(dkim_verify(message.encoded, public_key)).to be(true),
            "expected #{header_canon}/#{body_canon} signature to verify"
        end
      end
    end

    it "verifies a non-ASCII body for all canonicalization combinations" do
      %i[simple relaxed].each do |header_canon|
        %i[simple relaxed].each do |body_canon|
          message = build_message
          message.body = "Grüße  \t\r\n第二行\r\n\r\n"
          sign(message, :header_canonicalization => header_canon, :body_canonicalization => body_canon)
          expect(dkim_verify(message.encoded, public_key)).to be(true),
            "expected #{header_canon}/#{body_canon} signature to verify"
        end
      end
    end

    it "verifies a multipart message" do
      message = Mail.new do
        from "alice@example.com"
        to   "bob@example.net"
        subject "multipart"
        text_part { body "plain text" }
        html_part { content_type "text/html"; body "<p>html</p>" }
      end
      sign(message)
      expect(dkim_verify(message.encoded, public_key)).to be(true)
    end

    it "verifies a message with a non-ASCII body after encoding negotiation" do
      message = build_message
      message.body = "Grüße aus Köln\n第二行"
      sign(message)
      expect(message.content_transfer_encoding).not_to be_nil
      expect(dkim_verify(message.encoded, public_key)).to be(true)
    end

    it "verifies a message with an empty body against the known empty-sha256 value" do
      message = build_message
      message.body = ""
      sign(message)
      # base64(sha256("")) is a well-known constant
      expect(dkim_tags(message)["bh"]).to eq "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
      expect(dkim_verify(message.encoded, public_key)).to be(true)
    end

    it "accepts a PEM-encoded private key" do
      message = sign(build_message, :private_key => private_key.to_pem)
      expect(dkim_verify(message.encoded, public_key)).to be(true)
    end

    it "signs with a given identity" do
      message = sign(build_message, :identity => "alice@example.com")
      expect(dkim_tags(message)["i"]).to eq "alice@example.com"
      expect(dkim_verify(message.encoded, public_key)).to be(true)
    end

    it "produces signatures over bytes that later output does not modify" do
      message = build_message
      message.body = "Grüße\n"
      sign(message)
      first = message.encoded
      expect(message.encoded).to eq first
      expect(message.to_s).to eq first
      expect(dkim_verify(first, public_key)).to be(true)
      expect(dkim_verify(message.encoded, public_key)).to be(true)
    end

    it "returns the message" do
      message = build_message
      expect(sign(message)).to equal message
    end
  end

  describe "repeated header fields" do
    def add_received(message, text)
      message.header.fields << Mail::Field.parse("Received: #{text}")
    end

    it "signs repeated headers bottom-most first per RFC 6376 5.4.2" do
      message = build_message
      add_received(message, "from a.example by b.example; 1 Jan 2020 00:00:00 -0000")
      add_received(message, "from b.example by c.example; 1 Jan 2020 00:01:00 -0000")
      sign(message, :headers => %w[from received received])
      expect(dkim_tags(message)["h"]).to eq "from:received:received"
      expect(dkim_verify(message.encoded, public_key)).to be(true)
    end

    it "detects tampering with a signed instance of a repeated header" do
      message = build_message
      add_received(message, "from a.example by b.example; 1 Jan 2020 00:00:00 -0000")
      add_received(message, "from b.example by c.example; 1 Jan 2020 00:01:00 -0000")
      sign(message, :headers => %w[from received received])
      raw = message.encoded
      expect(dkim_verify(raw, public_key)).to be(true)
      tampered = raw.sub("by c.example", "by evil.example")
      expect(dkim_verify(tampered, public_key)).to be(false)
    end

    it "oversigns names so no further instance can be added" do
      message = build_message
      sign(message, :headers => %w[from from])
      expect(dkim_tags(message)["h"]).to eq "from:from"
      expect(dkim_verify(message.encoded, public_key)).to be(true)
      message.header.fields << Mail::Field.parse("From: mallory@evil.example")
      expect(dkim_verify(message.encoded, public_key)).to be(false)
    end
  end

  describe "signature integrity" do
    it "fails verification when the body changes after signing" do
      message = sign(build_message)
      raw = message.encoded
      expect(dkim_verify(raw, public_key)).to be(true)
      expect(dkim_verify(raw.sub("sealed", "opened"), public_key)).to be(false)
    end

    it "fails verification when a signed header changes after signing" do
      message = sign(build_message)
      raw = message.encoded
      expect(dkim_verify(raw.sub("hello there", "goodbye now"), public_key)).to be(false)
    end

    it "still verifies when an unsigned header is added" do
      message = sign(build_message)
      message.header["X-Comment"] = "added later"
      expect(dkim_verify(message.encoded, public_key)).to be(true)
    end

    it "fails verification with a different public key" do
      message = sign(build_message)
      expect(dkim_verify(message.encoded, OpenSSL::PKey::RSA.generate(2048).public_key)).to be(false)
    end
  end

  describe "multiple signatures" do
    it "supports signing a message twice with different selectors" do
      message = sign(build_message)
      other_key = OpenSSL::PKey::RSA.generate(2048)
      message.dkim_sign(:domain => "example.net", :selector => "s2",
                        :private_key => other_key, :time => 1_700_000_001)
      raw = message.encoded
      expect(raw.scan(/^DKIM-Signature:/).size).to eq 2
      expect(dkim_verify(raw, public_key, 0)).to be(true)
      expect(dkim_verify(raw, other_key.public_key, 1)).to be(true)
    end
  end

  describe "fixed test vector" do
    # A fixed RSA key and fixed message must always produce the exact same
    # signature bytes, guarding against canonicalization regressions.
    let(:vector_key) { OpenSSL::PKey::RSA.new(read_raw_fixture("dkim", "vector_key.pem")) }

    def vector_message
      message = Mail.new
      message.from "alice@example.com"
      message.to "bob@example.net"
      message.subject "DKIM vector"
      message.message_id "<vector.1@example.com>"
      message.date Time.utc(2026, 1, 2, 3, 4, 5)
      message.body = "Hello, DKIM!\r\nSecond line.\r\n"
      message
    end

    it "reproduces the known signature byte-for-byte" do
      message = vector_message
      message.dkim_sign(:domain => "example.com", :selector => "vec",
                        :private_key => vector_key, :time => 1_767_321_845,
                        :canonicalization => :relaxed)
      expect(message.encoded).to eq read_raw_fixture("dkim", "vector.eml")
    end

    it "verifies the known signature with the independent verifier" do
      expect(dkim_verify(read_raw_fixture("dkim", "vector.eml"), vector_key.public_key)).to be(true)
    end
  end

  describe "round trips" do
    it "keeps the signature readable after parsing the encoded message" do
      message = sign(build_message)
      parsed = Mail.new(message.encoded)
      expect(parsed["dkim-signature"]).not_to be_nil
      expect(parsed["dkim-signature"].value).to include "d=example.com"
    end
  end
end
