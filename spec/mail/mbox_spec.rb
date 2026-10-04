# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'
require 'stringio'

RSpec.describe Mail::Mbox do
  # An IO-like source that only supports read(length), proving the reader
  # never slurps the whole archive or falls back to line-based IO methods.
  class ChunkedSource
    def initialize(data)
      @data = data
      @offset = 0
    end

    def read(length)
      raise 'read called without a length' unless length
      return nil if @offset >= @data.bytesize

      chunk = @data.byteslice(@offset, length)
      @offset += chunk.bytesize
      chunk
    end
  end

  def mbox_reader(data, chunk_size: nil)
    source = ChunkedSource.new(data)
    if chunk_size
      Mail::Mbox::Reader.new(source, chunk_size: chunk_size)
    else
      Mail::Mbox::Reader.new(source)
    end
  end

  let(:alice_raw) do
    "From: alice@example.com\r\nSubject: Hello Alice\r\n\r\nfirst line\r\nsecond line\r\n"
  end

  let(:bob_raw) do
    "From: bob@example.com\r\nSubject: Hello Bob\r\n\r\nonly line\r\n"
  end

  let(:archive) do
    "From alice@example.com Thu Oct  2 10:00:00 2026\n" +
      alice_raw +
      "\n" +
      "From bob@example.com Fri Oct  3 11:30:00 2026\n" +
      bob_raw +
      "\n"
  end

  describe Mail::Mbox::Reader do
    it 'yields one Mail::Message per message in the archive' do
      messages = mbox_reader(archive).to_a
      expect(messages.length).to eq(2)
      expect(messages).to all(be_a(Mail::Message))
      expect(messages.map(&:subject)).to eq(['Hello Alice', 'Hello Bob'])
    end

    it 'preserves the usable envelope sender and time from the From_ line' do
      message = mbox_reader(archive).first
      expect(message.mbox_envelope_sender).to eq('alice@example.com')
      expect(message.mbox_envelope_time).to eq(Time.local(2026, 10, 2, 10, 0, 0))
    end

    it 'leaves the envelope time nil when the date cannot be parsed' do
      data = "From carol@example.com not-a-date\n" + alice_raw
      message = mbox_reader(data).first
      expect(message.mbox_envelope_sender).to eq('carol@example.com')
      expect(message.mbox_envelope_time).to be_nil
    end

    it 'distinguishes the envelope From_ line from escaped body From lines' do
      raw = "From: dave@example.com\nSubject: quoted\n\nFrom not a separator\n>From already quoted\n>>From doubly quoted\n> not from at all\n"
      data = "From dave@example.com Thu Oct  2 10:00:00 2026\n" + raw.gsub(/^(>*From )/, '>\\1') + "\n"
      messages = mbox_reader(data).to_a
      expect(messages.length).to eq(1)
      body = messages.first.body.to_s
      expect(body).to include("From not a separator\n")
      expect(body).to include(">From already quoted\n")
      expect(body).to include(">>From doubly quoted\n")
      expect(body).to include("> not from at all\n")
    end

    it 'produces identical results no matter where chunk boundaries fall' do
      fingerprint = ->(m) { [m.subject, m.from, m.body.to_s] }
      expected = mbox_reader(archive).map(&fingerprint)
      (1..7).each do |size|
        expect(mbox_reader(archive, chunk_size: size).map(&fingerprint)).to eq(expected)
      end
    end

    it 'does not split a message when a chunk starts with an escaped From line' do
      raw = "Subject: chunked\n\nab\n>From escaped\ncd\n"
      data = "From e@example.com Thu Oct  2 10:00:00 2026\n" + raw + "\n"
      # chunk size 3 puts a chunk boundary right before the escaped From line
      messages = mbox_reader(data, chunk_size: 3).to_a
      expect(messages.length).to eq(1)
      expect(messages.first.body.to_s).to include("From escaped\n")
    end

    it 'yields the final message even without a trailing newline' do
      data = "From f@example.com Thu Oct  2 10:00:00 2026\nSubject: no newline\n\nbody without newline"
      messages = mbox_reader(data, chunk_size: 2).to_a
      expect(messages.length).to eq(1)
      expect(messages.first.subject).to eq('no newline')
      expect(messages.first.body.to_s).to eq('body without newline')
    end

    it 'ignores content before the first From_ separator' do
      data = "garbage preamble\nmore garbage\nFrom g@example.com Thu Oct  2 10:00:00 2026\nSubject: real\n\nbody\n"
      messages = mbox_reader(data).to_a
      expect(messages.length).to eq(1)
      expect(messages.first.subject).to eq('real')
    end

    it 'yields nothing for an empty archive' do
      expect(mbox_reader('').to_a).to eq([])
    end

    it 'returns an enumerator when each is called without a block' do
      expect(mbox_reader(archive).each).to be_a(Enumerator)
    end
  end

  describe Mail::Mbox::Writer do
    def write_to_string(messages)
      io = StringIO.new
      Mail::Mbox::Writer.new(io).write(messages)
      io.string
    end

    it 'accepts any enumerable of messages' do
      messages = [Mail.new(alice_raw), Mail.new(bob_raw)].lazy
      output = write_to_string(messages)
      expect(output.scan(/^From /).length).to eq(2)
    end

    it 'derives the envelope line from the From header and Date' do
      message = Mail.new(from: 'alice@example.com', date: 'Thu, 02 Oct 2026 10:00:00 +0800', body: 'hi')
      output = write_to_string([message])
      expect(output).to start_with("From alice@example.com Fri Oct  2 10:00:00 2026\n")
    end

    it 'prefers preserved envelope metadata when present' do
      message = Mail.new(from: 'alice@example.com', body: 'hi')
      message.extend(Mail::Mbox::Envelope)
      message.mbox_envelope_sender = 'bounce@example.org'
      message.mbox_envelope_time = Time.utc(2026, 1, 2, 3, 4, 5)
      output = write_to_string([message])
      expect(output).to start_with("From bounce@example.org Fri Jan  2 03:04:05 2026\n")
    end

    it 'escapes From lines and already-quoted From lines in the body' do
      message = Mail.new(subject: 'esc', body: "From a\n>From b\n>>From c\n> plain\n")
      output = write_to_string([message]).gsub("\r\n", "\n")
      expect(output).to include("\n>From a\n")
      expect(output).to include("\n>>From b\n")
      expect(output).to include("\n>>>From c\n")
      expect(output).to include("\n> plain\n")
    end

    it 'terminates a message that does not end with a newline' do
      output = write_to_string(['Subject: raw'])
      expect(output).to match(/\AFrom MAILER-DAEMON .+\nSubject: raw\n\n\z/)
    end

    it 'round-trips messages through the reader' do
      original = Mail.new(from: 'alice@example.com', subject: 'round trip',
                          body: "hello\nFrom sneaky\n>>From sneakier\nbye\n")
      messages = Mail::Mbox::Reader.new(StringIO.new(write_to_string([original]))).to_a
      expect(messages.length).to eq(1)
      expect(messages.first.subject).to eq('round trip')
      expect(messages.first.body.to_s).to eq(original.body.to_s)
    end
  end
end
