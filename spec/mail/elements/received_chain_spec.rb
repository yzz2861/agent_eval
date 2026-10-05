# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::ReceivedChain do
  let(:newest) do
    'from edge.example (note with id; for and ;) by final.example with ESMTP id ABC123 for <user@example.com>; Mon, 5 Oct 2026 10:05:00 +0800'
  end

  let(:middle) do
    "from middle.example\r\n\tby edge.example via TCP id MID-456; Mon, 5 Oct 2026 10:00:00 +0800"
  end

  let(:oldest) do
    'from origin.example by middle.example; Mon, 5 Oct 2026 09:55:00 +0800'
  end

  let(:header) do
    Mail::Header.new([
      "Received: #{newest}",
      "Received: #{middle}",
      "Received: #{oldest}"
    ].join("\r\n"))
  end

  it 'parses the received fields in their original order' do
    chain = header.received_chain

    expect(chain.map(&:from)).to eq [
      'edge.example (note with id; for and ;)',
      'middle.example',
      'origin.example'
    ]
    expect(chain.map(&:by)).to eq ['final.example', 'edge.example', 'middle.example']
    expect(chain.map(&:delay_seconds)).to eq [nil, 300, 300]
  end

  it 'parses structured values and preserves unknown fragments and raw fields' do
    hop = header.received_chain.first

    expect(hop.with).to eq 'ESMTP'
    expect(hop.id).to eq 'ABC123'
    expect(hop.for).to eq '<user@example.com>'
    expect(hop.date).to eq 'Mon, 5 Oct 2026 10:05:00 +0800'
    expect(hop.date_time).to eq DateTime.parse('Mon, 5 Oct 2026 10:05:00 +0800')
    expect(hop.raw).to eq newest
    expect(hop.raw_field).to eq "Received: #{newest}"
    expect(header.received_chain.raw_fields.first).to eq "Received: #{newest}"

    middle_hop = header.received_chain[1]
    expect(middle_hop.unrecognized).to eq ['via TCP']
    expect(middle_hop.unknown).to eq ['via TCP']
  end

  it 'unfolds wrapped fields before parsing' do
    hop = header.received_chain[1]

    expect(hop.raw).to include("\r\n\t")
    expect(hop.from).to eq 'middle.example'
    expect(hop.by).to eq 'edge.example'
    expect(hop.id).to eq 'MID-456'
  end

  it 'parses a single field body passed directly to the chain reader' do
    hop = described_class.parse(newest).first

    expect(hop.from).to eq 'edge.example (note with id; for and ;)'
    expect(hop.by).to eq 'final.example'
    expect(hop.id).to eq 'ABC123'
  end

  it 'does not treat keywords followed by atom characters as field markers' do
    hop = described_class.parse([
      'from sender.for.example by final.example; Mon, 5 Oct 2026 10:05:00 +0800'
    ]).first

    expect(hop.from).to eq 'sender.for.example'
    expect(hop.for).to be_nil
  end

  it 'does not split on keywords or semicolons inside comments' do
    hop = described_class.parse([
      'from edge.example (queue; from x by y with z id 1 for 2) by final.example; Mon, 5 Oct 2026 10:05:00 +0800'
    ]).first

    expect(hop.from).to eq 'edge.example (queue; from x by y with z id 1 for 2)'
    expect(hop.by).to eq 'final.example'
    expect(hop.with).to be_nil
    expect(hop.id).to be_nil
    expect(hop.for).to be_nil
  end

  it 'keeps negative delays without reordering hops' do
    backwards = Mail::Header.new([
      "Received: from a.example by b.example; Mon, 5 Oct 2026 10:00:00 +0800",
      "Received: from c.example by d.example; Mon, 5 Oct 2026 10:10:00 +0800"
    ].join("\r\n")).received_chain

    expect(backwards.map(&:from)).to eq ['a.example', 'c.example']
    expect(backwards.last.delay_seconds).to eq(-600)
    expect(backwards.last).to be_negative_delay
  end

  it 'marks missing times and preserves adjacent hops' do
    incomplete_header = Mail::Header.new([
      "Received: #{newest}",
      'Received: from broken.example by final.example',
      "Received: #{oldest}"
    ].join("\r\n"))
    chain = incomplete_header.received_chain

    expect(chain.size).to eq 3
    expect(chain[0].from).to eq 'edge.example (note with id; for and ;)'
    expect(chain[1].from).to eq 'broken.example'
    expect(chain[1]).to be_delay_missing
    expect(chain[2].from).to eq 'origin.example'
    expect(chain[2]).to be_delay_missing
  end

  it 'keeps the other hops when one hop cannot be parsed' do
    bad_header = Mail::Header.new([
      "Received: #{newest}",
      'Received: from broken.example (unclosed comment by final.example',
      "Received: #{oldest}"
    ].join("\r\n"))
    chain = bad_header.received_chain

    expect(chain.size).to eq 3
    expect(chain[0].id).to eq 'ABC123'
    expect(chain[1].id).to be_nil
    expect(chain[1].error).to be_a(Mail::Field::ParseError)
    expect(chain[1]).to be_delay_missing
    expect(chain[2].from).to eq 'origin.example'
  end

  it 'exposes a readable relay chain' do
    output = header.received_chain.to_s

    expect(output).to eq [
      '1/3: edge.example (note with id; for and ;) -> final.example via ESMTP for <user@example.com> at Mon, 5 Oct 2026 10:05:00 +0800 (delay unknown)',
      '2/3: middle.example -> edge.example [via TCP] at Mon, 5 Oct 2026 10:00:00 +0800 (300s)',
      '3/3: origin.example -> middle.example at Mon, 5 Oct 2026 09:55:00 +0800 (300s)'
    ].join("\n")
  end
end
