# encoding: utf-8
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Mail::PartialCollector do
  let(:collector) { Mail::PartialCollector.new }

  def fragment_source(id:, number:, payload:, total: nil, headers: [])
    lines = headers.dup
    content_type = %(Content-Type: message/partial; id="#{id}"; number=#{number})
    content_type += "; total=#{total}" if total
    lines << content_type
    lines << 'MIME-Version: 1.0'
    lines.join("\r\n") + "\r\n\r\n" + payload
  end

  def split_source(source, count)
    size = (source.length.to_f / count).ceil
    source.scan(/.{1,#{size}}/m)
  end

  let(:original_source) do
    "From: Inner Sender <inner@example.com>\r\n" \
    "To: inner-to@example.com\r\n" \
    "Subject: Reassembled notice\r\n" \
    "Message-ID: <original@example.com>\r\n" \
    "X-Inner: should-be-dropped\r\n" \
    "Content-Type: text/plain; charset=us-ascii\r\n" \
    "MIME-Version: 1.0\r\n" \
    "\r\n" \
    "Hello, this is the original body.\r\n" \
    "It has two lines.\r\n"
  end

  def outer_headers(number)
    [
      'From: Outer Gateway <outer@example.com>',
      'To: outer-to@example.com',
      "Subject: fragment #{number} of the day",
      "Message-ID: <fragment-#{number}@partial.example.com>",
      'Date: Thu, 01 Oct 2026 10:00:00 +0800'
    ]
  end

  describe 'reassembling' do
    it 'restores the original message from out-of-order fragments' do
      chunks = split_source(original_source, 3)
      expect(chunks.size).to eq 3

      expect(collector.add(fragment_source(id: 'm1', number: 2, payload: chunks[1], headers: outer_headers(2)))).to eq :stored
      expect(collector.add(fragment_source(id: 'm1', number: 3, payload: chunks[2], total: 3, headers: outer_headers(3)))).to eq :stored
      expect(collector.complete?('m1')).to be false
      expect(collector.add(fragment_source(id: 'm1', number: 1, payload: chunks[0], headers: outer_headers(1)))).to eq :complete

      expect(collector.complete?('m1')).to be true
      message = collector.message('m1')
      expect(message).to be_a Mail::Message
      expect(message.subject).to eq 'Reassembled notice'
      expect(message.body.raw_source).to eq "Hello, this is the original body.\r\nIt has two lines.\r\n"
      expect(message.body.decoded).to eq "Hello, this is the original body.\nIt has two lines.\n"
    end

    it 'keeps enclosing headers and takes Content-* and friends from the inner message' do
      chunks = split_source(original_source, 2)
      collector.add(fragment_source(id: 'm2', number: 1, payload: chunks[0], total: 2, headers: outer_headers(1)))
      collector.add(fragment_source(id: 'm2', number: 2, payload: chunks[1], headers: outer_headers(2)))

      message = collector.message('m2')
      expect(message.from).to eq ['outer@example.com']
      expect(message.to).to eq ['outer-to@example.com']
      expect(message.date).to eq DateTime.parse('2026-10-01 10:00:00 +0800')
      expect(message.subject).to eq 'Reassembled notice'
      expect(message.message_id).to eq 'original@example.com'
      expect(message.mime_version).to eq '1.0'
      expect(message.content_type).to eq 'text/plain; charset=us-ascii'
    end

    it 'ignores inner headers that are not Content-* or the named fields' do
      chunks = split_source(original_source, 2)
      collector.add(fragment_source(id: 'm3', number: 1, payload: chunks[0], total: 2, headers: outer_headers(1)))
      collector.add(fragment_source(id: 'm3', number: 2, payload: chunks[1], headers: outer_headers(2)))

      message = collector.message('m3')
      expect(message.header['X-Inner']).to be_nil
      expect(message[:from].addresses).to eq ['outer@example.com']
      expect(message.header['To'].value).to eq 'outer-to@example.com'
    end

    it 'reassembles a multipart inner message' do
      boundary = 'partial-boundary-42'
      inner =
        "From: a@example.com\r\n" \
        "Subject: multi\r\n" \
        "Content-Type: multipart/mixed; boundary=#{boundary}\r\n" \
        "\r\n" \
        "--#{boundary}\r\n" \
        "Content-Type: text/plain\r\n" \
        "\r\n" \
        "first part\r\n" \
        "--#{boundary}\r\n" \
        "Content-Type: text/html\r\n" \
        "\r\n" \
        "<p>second</p>\r\n" \
        "--#{boundary}--\r\n"
      chunks = split_source(inner, 3)

      collector.add(fragment_source(id: 'm4', number: 3, payload: chunks[2], total: 3))
      collector.add(fragment_source(id: 'm4', number: 1, payload: chunks[0]))
      collector.add(fragment_source(id: 'm4', number: 2, payload: chunks[1]))

      message = collector.message('m4')
      expect(message).to be_multipart
      expect(message.parts.size).to eq 2
      expect(message.parts[0].decoded).to include 'first part'
      expect(message.parts[1].decoded).to include '<p>second</p>'
    end

    it 'accepts Mail::Message instances as fragments' do
      chunks = split_source(original_source, 2)
      collector.add(Mail.new(fragment_source(id: 'm5', number: 1, payload: chunks[0], total: 2)))
      collector.add(Mail.new(fragment_source(id: 'm5', number: 2, payload: chunks[1])))

      expect(collector.message('m5').subject).to eq 'Reassembled notice'
    end
  end

  describe 'tracking' do
    it 'reports missing fragments once total is known' do
      chunks = split_source(original_source, 3)
      collector.add(fragment_source(id: 't1', number: 1, payload: chunks[0]))
      expect(collector.missing('t1')).to be_nil
      expect(collector.total('t1')).to be_nil

      collector.add(fragment_source(id: 't1', number: 3, payload: chunks[2], total: 3))
      expect(collector.total('t1')).to eq 3
      expect(collector.missing('t1')).to eq [2]
      expect(collector.received('t1')).to eq [1, 3]

      collector.add(fragment_source(id: 't1', number: 2, payload: chunks[1]))
      expect(collector.missing('t1')).to eq []
    end

    it 'tracks several ids independently' do
      chunks = split_source(original_source, 2)
      collector.add(fragment_source(id: 'a', number: 1, payload: chunks[0], total: 2))
      collector.add(fragment_source(id: 'b', number: 1, payload: chunks[0], total: 2))

      expect(collector.ids).to contain_exactly('a', 'b')
      collector.add(fragment_source(id: 'a', number: 2, payload: chunks[1]))
      expect(collector.complete?('a')).to be true
      expect(collector.complete?('b')).to be false
      expect(collector.missing('b')).to eq [2]
    end

    it 'returns neutral values for unknown ids' do
      expect(collector.missing('nope')).to be_nil
      expect(collector.received('nope')).to eq []
      expect(collector.total('nope')).to be_nil
      expect(collector.complete?('nope')).to be false
      expect(collector.conflict?('nope')).to be false
      expect(collector.conflicts('nope')).to eq []
      expect(collector.message('nope')).to be_nil
      expect(collector.discard('nope')).to be false
    end
  end

  describe 'duplicates and conflicts' do
    it 'ignores an identical repeated fragment' do
      chunks = split_source(original_source, 2)
      source = fragment_source(id: 'd1', number: 1, payload: chunks[0], total: 2)
      expect(collector.add(source)).to eq :stored
      expect(collector.add(source)).to eq :duplicate
      expect(collector.received('d1')).to eq [1]
      expect(collector.conflict?('d1')).to be false

      expect(collector.add(fragment_source(id: 'd1', number: 2, payload: chunks[1]))).to eq :complete
      expect(collector.message('d1').subject).to eq 'Reassembled notice'
    end

    it 'treats a repeat with different outer headers but same payload as duplicate' do
      chunks = split_source(original_source, 2)
      collector.add(fragment_source(id: 'd2', number: 1, payload: chunks[0], total: 2))
      duplicate = fragment_source(id: 'd2', number: 1, payload: chunks[0], total: 2,
                                  headers: ['Received: by other.example.com'])
      expect(collector.add(duplicate)).to eq :duplicate
    end

    it 'keeps a conflicting fragment and stops assembling' do
      chunks = split_source(original_source, 2)
      collector.add(fragment_source(id: 'd3', number: 1, payload: chunks[0], total: 2))
      expect(collector.add(fragment_source(id: 'd3', number: 1, payload: 'tampered payload', total: 2))).to eq :conflict

      expect(collector.conflict?('d3')).to be true
      conflict = collector.conflicts('d3').first
      expect(conflict.number).to eq 1
      expect(conflict.reason).to eq :fragment_mismatch
      expect(conflict.existing).to be_a Mail::Message
      expect(conflict.incoming.body.raw_source).to eq 'tampered payload'

      collector.add(fragment_source(id: 'd3', number: 2, payload: chunks[1]))
      expect(collector.complete?('d3')).to be false
      expect(collector.message('d3')).to be_nil
    end

    it 'records a conflict when fragments disagree on total' do
      chunks = split_source(original_source, 3)
      collector.add(fragment_source(id: 'd4', number: 1, payload: chunks[0], total: 3))
      expect(collector.add(fragment_source(id: 'd4', number: 2, payload: chunks[1], total: 4))).to eq :conflict

      conflict = collector.conflicts('d4').first
      expect(conflict.reason).to eq :total_mismatch
      expect(collector.total('d4')).to eq 3
    end

    it 'records a conflict when a fragment number exceeds the known total' do
      chunks = split_source(original_source, 2)
      collector.add(fragment_source(id: 'd5', number: 1, payload: chunks[0], total: 2))
      expect(collector.add(fragment_source(id: 'd5', number: 3, payload: 'extra'))).to eq :conflict
      expect(collector.conflicts('d5').first.reason).to eq :number_exceeds_total
    end
  end

  describe 'discarding' do
    it 'drops all state for an id' do
      chunks = split_source(original_source, 2)
      collector.add(fragment_source(id: 'x1', number: 1, payload: chunks[0], total: 2))
      expect(collector.discard('x1')).to be true
      expect(collector.discard('x1')).to be false
      expect(collector.ids).to be_empty
      expect(collector.missing('x1')).to be_nil
    end

    it 'allows a discarded id to be collected again' do
      chunks = split_source(original_source, 2)
      collector.add(fragment_source(id: 'x2', number: 1, payload: 'tampered payload', total: 2))
      collector.add(fragment_source(id: 'x2', number: 1, payload: chunks[0], total: 2))
      expect(collector.conflict?('x2')).to be true

      collector.discard('x2')
      collector.add(fragment_source(id: 'x2', number: 1, payload: chunks[0], total: 2))
      collector.add(fragment_source(id: 'x2', number: 2, payload: chunks[1]))
      expect(collector.message('x2').subject).to eq 'Reassembled notice'
    end

    it 'clears everything at once' do
      chunks = split_source(original_source, 2)
      collector.add(fragment_source(id: 'x3', number: 1, payload: chunks[0], total: 2))
      collector.clear
      expect(collector.ids).to be_empty
    end
  end

  describe 'validation' do
    it 'rejects messages that are not message/partial' do
      expect {
        collector.add("Content-Type: text/plain\r\n\r\nhello")
      }.to raise_error(ArgumentError, /message\/partial/)
    end

    it 'rejects fragments without an id parameter' do
      expect {
        collector.add("Content-Type: message/partial; number=1\r\n\r\nchunk")
      }.to raise_error(ArgumentError, /id/)
    end

    it 'rejects fragments without a number parameter' do
      expect {
        collector.add('Content-Type: message/partial; id="abc"' + "\r\n\r\nchunk")
      }.to raise_error(ArgumentError, /number/)
    end

    it 'rejects fragments with a non-positive number' do
      expect {
        collector.add('Content-Type: message/partial; id="abc"; number=0' + "\r\n\r\nchunk")
      }.to raise_error(ArgumentError, /number/)
    end
  end
end
