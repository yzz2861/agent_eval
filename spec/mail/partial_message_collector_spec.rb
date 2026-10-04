# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::PartialMessageCollector do
  CRLF = "\r\n"

  # The message the sending agent chopped into message/partial pieces.
  def inner_lines
    [
      'Content-Type: text/plain; charset=us-ascii',
      'Content-Transfer-Encoding: 7bit',
      'Message-ID: <inner-123@example.com>',
      'MIME-Version: 1.0',
      'X-Inner-Note: drop-me',
      '',
      'Hello, this is the first body line.',
      'And a second one.',
      'The end.'
    ]
  end

  # Split at line boundaries; the inner header block itself spans
  # fragments 1 and 2, as RFC 2046 permits.
  def inner_parts
    lines = inner_lines.map { |line| line + CRLF }
    [lines[0..2].join, lines[3..6].join, lines[7..-1].join]
  end

  def inner_body
    [
      'Hello, this is the first body line.',
      'And a second one.',
      'The end.'
    ].join(CRLF) + CRLF
  end

  def fragment(id:, number:, payload:, total: nil, subject: nil, extra: [])
    subject ||= "part #{number}"
    content_type = +"Content-Type: message/partial; id=\"#{id}\"; number=#{number}"
    content_type << "; total=#{total}" if total
    headers = [
      'From: sender@example.com',
      'To: collector@example.com',
      "Subject: #{subject}",
      'Date: Thu, 01 Oct 2026 10:00:00 +0800',
      "Message-ID: <outer-#{number}@example.com>",
      'MIME-Version: 1.0',
      *extra,
      content_type
    ]
    headers.join(CRLF) + CRLF + CRLF + payload
  end

  let(:collector) { described_class.new }
  let(:parts) { inner_parts }

  def add_all(id, totals_on: 3)
    parts.each_with_index do |payload, index|
      number = index + 1
      total = number == totals_on ? parts.length : nil
      collector.add(fragment(id: id, number: number, payload: payload, total: total))
    end
  end

  describe '#add' do
    it 'stores fragments received out of order' do
      expect(collector.add(fragment(id: 'a', number: 2, payload: parts[1]))).to eq :stored
      expect(collector.add(fragment(id: 'a', number: 1, payload: parts[0]))).to eq :stored
      expect(collector.received('a')).to eq [1, 2]
    end

    it 'accepts Mail::Message instances as well as raw strings' do
      expect(collector.add(Mail.new(fragment(id: 'a', number: 1, payload: parts[0])))).to eq :stored
      expect(collector.received('a')).to eq [1]
    end

    it 'tracks ids independently' do
      collector.add(fragment(id: 'a', number: 1, payload: parts[0]))
      collector.add(fragment(id: 'b', number: 1, payload: parts[0]))
      expect(collector.ids).to contain_exactly('a', 'b')
    end

    it 'ignores a repeated fragment with an identical payload' do
      same = fragment(id: 'a', number: 1, payload: parts[0])
      expect(collector.add(same)).to eq :stored
      expect(collector.add(same)).to eq :duplicate
      expect(collector.received('a')).to eq [1]
      expect(collector.conflict?('a')).to be false
    end

    it 'keeps a repeated fragment with a different payload as a conflict' do
      collector.add(fragment(id: 'a', number: 1, payload: 'first payload'))
      expect(collector.add(fragment(id: 'a', number: 1, payload: 'changed payload'))).to eq :conflict
      expect(collector.conflict?('a')).to be true

      conflict = collector.conflicts('a').first
      expect(conflict.number).to eq 1
      expect(conflict.reason).to eq :mismatched_fragment
      expect(conflict.stored).to include('first payload')
      expect(conflict.received).to include('changed payload')
    end

    it 'keeps a contradictory total as a conflict' do
      collector.add(fragment(id: 'a', number: 1, total: 2, payload: parts[0]))
      expect(collector.add(fragment(id: 'a', number: 2, total: 3, payload: parts[1]))).to eq :conflict

      conflict = collector.conflicts('a').first
      expect(conflict.reason).to eq :mismatched_total
      expect(conflict.stored).to eq 2
      expect(conflict.received).to eq 3
    end

    it 'keeps a fragment numbered beyond the announced total as a conflict' do
      collector.add(fragment(id: 'a', number: 1, total: 1, payload: parts[0]))
      expect(collector.add(fragment(id: 'a', number: 2, payload: parts[1]))).to eq :conflict
      expect(collector.conflicts('a').first.reason).to eq :number_out_of_range
    end

    it 'raises ArgumentError for messages that are not message/partial' do
      expect { collector.add("Subject: plain#{CRLF}#{CRLF}body#{CRLF}") }.to raise_error(ArgumentError)
    end

    it 'raises ArgumentError when the id or number parameter is missing' do
      expect { collector.add("Content-Type: message/partial; number=1#{CRLF}#{CRLF}x") }.to raise_error(ArgumentError)
      expect { collector.add("Content-Type: message/partial; id=\"a\"#{CRLF}#{CRLF}x") }.to raise_error(ArgumentError)
    end
  end

  describe 'completeness' do
    it 'is incomplete until total is known and every fragment arrived' do
      collector.add(fragment(id: 'a', number: 1, payload: parts[0]))
      expect(collector.complete?('a')).to be false
      expect(collector.missing('a')).to be_nil

      collector.add(fragment(id: 'a', number: 3, total: 3, payload: parts[2]))
      expect(collector.complete?('a')).to be false
      expect(collector.missing('a')).to eq [2]

      collector.add(fragment(id: 'a', number: 2, payload: parts[1]))
      expect(collector.complete?('a')).to be true
      expect(collector.missing('a')).to eq []
    end

    it 'allows total to arrive on a fragment other than the last one' do
      collector.add(fragment(id: 'a', number: 1, total: 3, payload: parts[0]))
      expect(collector.total('a')).to eq 3
      expect(collector.missing('a')).to eq [2, 3]
    end

    it 'stays incomplete forever once a conflict was recorded' do
      collector.add(fragment(id: 'a', number: 1, payload: 'one'))
      collector.add(fragment(id: 'a', number: 1, payload: 'two'))
      collector.add(fragment(id: 'a', number: 2, total: 2, payload: 'rest'))
      expect(collector.complete?('a')).to be false
      expect(collector.reassemble('a')).to be_nil
    end
  end

  describe '#reassemble' do
    it 'returns nil for unknown or incomplete ids' do
      expect(collector.reassemble('nope')).to be_nil
      collector.add(fragment(id: 'a', number: 1, payload: parts[0]))
      expect(collector.reassemble('a')).to be_nil
    end

    it 'restores the original message from out-of-order fragments' do
      collector.add(fragment(id: 'a', number: 3, total: 3, payload: parts[2]))
      collector.add(fragment(id: 'a', number: 1, payload: parts[0]))
      collector.add(fragment(id: 'a', number: 2, payload: parts[1]))

      mail = collector.reassemble('a')
      expect(mail).to be_a(Mail::Message)
      expect(mail.raw_source).to include(inner_body)
      expect(mail.body.decoded).to eq inner_body.gsub(/\r\n/, "\n")
    end

    it 'copies non-content headers from the first enclosing entity' do
      add_all('a')
      mail = collector.reassemble('a')
      expect(mail.subject).to eq 'part 1'
      expect(mail.from).to eq ['sender@example.com']
      expect(mail.to).to eq ['collector@example.com']
      expect(mail.date).not_to be_nil
    end

    it 'takes Content-* and Message-ID/Encrypted/MIME-Version headers from the enclosed message' do
      add_all('a')
      mail = collector.reassemble('a')
      expect(mail.mime_type).to eq 'text/plain'
      expect(mail.content_type_parameters).to eq('charset' => 'us-ascii')
      expect(mail.content_transfer_encoding).to eq '7bit'
      expect(mail.message_id).to eq 'inner-123@example.com'
      expect(mail.mime_version).to eq '1.0'
    end

    it 'drops enclosing Content-* headers and enclosed non-content headers' do
      add_all('a')
      mail = collector.reassemble('a')
      expect(mail.header['Content-Type'].value).not_to include('message/partial')
      expect(mail['X-Inner-Note']).to be_nil
    end

    it 'discards the headers of the second and subsequent enclosing entities' do
      parts.each_with_index do |payload, index|
        number = index + 1
        collector.add(fragment(id: 'a', number: number, payload: payload,
                               total: (3 if number == 3),
                               subject: "part #{number}",
                               extra: ["X-Enclosing-#{number}: yes"]))
      end
      mail = collector.reassemble('a')
      expect(mail.subject).to eq 'part 1'
      expect(mail['X-Enclosing-2']).to be_nil
      expect(mail['X-Enclosing-3']).to be_nil
    end
  end

  describe '#discard' do
    it 'drops every fragment and conflict for an id' do
      collector.add(fragment(id: 'a', number: 1, payload: 'one'))
      collector.add(fragment(id: 'a', number: 1, payload: 'two'))
      expect(collector.discard('a')).to be true
      expect(collector.ids).to be_empty
      expect(collector.conflict?('a')).to be false
      expect(collector.conflicts('a')).to eq []
      expect(collector.missing('a')).to be_nil
    end

    it 'returns false when nothing was stored for the id' do
      expect(collector.discard('nope')).to be false
    end
  end
end
