# encoding: utf-8
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Mail::ThreadIndex do
  def build_message(id, subject: 'Discussion', body: "Body #{id}", in_reply_to: nil, references: nil)
    Mail.new do
      message_id "<#{id}>"
      subject subject
      body body
      in_reply_to Array(in_reply_to).map { |ref| "<#{ref}>" }.join(' ') unless in_reply_to.nil?
      references Array(references).map { |ref| "<#{ref}>" }.join(' ') unless references.nil?
    end
  end

  def snapshot(index)
    {
      roots: index.root_ids,
      parents: index.root_ids.sort + index.parent_relationships.keys.sort.map do |parent_id|
        [parent_id, index.child_ids(parent_id)]
      end,
      unresolved_message_ids: index.unresolved_message_ids,
      unresolved_references: index.unresolved_references
    }
  end

  it 'creates placeholders for missing ancestors and merges them on arrival' do
    root = build_message('a@example')
    reply = build_message('b@example', in_reply_to: 'a@example', references: ['a@example'])
    followup = build_message(
      'c@example',
      in_reply_to: 'b@example',
      references: ['a@example', 'b@example']
    )

    index = described_class.new
    index.add(followup)

    expect(index.size).to eq 3
    expect(index.root_ids).to eq ['a@example']
    expect(index.parent_id('c@example')).to eq 'b@example'
    expect(index.parent_id('b@example')).to eq 'a@example'
    expect(index.unresolved_message_ids).to eq ['a@example', 'b@example']
    expect(index.unresolved_references).to eq(
      'c@example' => ['a@example', 'b@example']
    )

    index.add(reply)
    expect(index.placeholder?('b@example')).to eq false
    expect(index.message('b@example')).to equal(reply)
    expect(index.unresolved_message_ids).to eq ['a@example']

    index.add(root)
    expect(index.root_ids).to eq ['a@example']
    expect(index.parent_relationships).to eq(
      'a@example' => ['b@example'],
      'b@example' => ['c@example'],
      'c@example' => []
    )
    expect(index.unresolved_message_ids).to eq []
    expect(index.unresolved_references).to eq({})
  end

  it 'builds the same tree for every message arrival order' do
    messages = {
      'a@example' => build_message('a@example'),
      'b@example' => build_message(
        'b@example',
        in_reply_to: 'a@example',
        references: ['a@example']
      ),
      'c@example' => build_message(
        'c@example',
        in_reply_to: 'b@example',
        references: ['a@example', 'b@example']
      )
    }

    snapshots = messages.keys.permutation.map do |order|
      index = described_class.new
      order.each { |id| index.add(messages[id]) }
      snapshot(index)
    end

    expect(snapshots.uniq).to eq([
      {
        roots: ['a@example'],
        parents: [
          'a@example',
          ['a@example', ['b@example']],
          ['b@example', ['c@example']],
          ['c@example', []]
        ],
        unresolved_message_ids: [],
        unresolved_references: {}
      }
    ])
  end

  it 'uses the last References ID as parent when In-Reply-To is absent' do
    index = described_class.new
    index.add(build_message('c@example', references: ['a@example', 'b@example']))

    expect(index.parent_id('c@example')).to eq 'b@example'
  end

  it 'lets an arrived placeholder become a root when it has no parent headers' do
    followup = build_message(
      'c@example',
      references: ['a@example', 'b@example']
    )
    root = build_message('b@example')

    index = described_class.new
    index.add(followup)
    expect(index.parent_id('b@example')).to eq 'a@example'

    index.add(root)
    expect(index.root_ids).to eq ['a@example', 'b@example']
    expect(index.parent_id('b@example')).to be_nil
    expect(index.parent_id('c@example')).to eq 'b@example'
  end

  it 'reports different messages that use the same Message-ID' do
    first = build_message('a@example', body: 'first body')
    second = build_message('a@example', body: 'second body')
    duplicate = build_message('a@example', body: 'first body')

    index = described_class.new
    index.add(first)
    index.add(second)
    index.add(duplicate)

    expect(index.conflict?).to eq true
    expect(index.conflict?('a@example')).to eq true
    expect(index.conflicts.map(&:message_id)).to eq ['a@example']
    expect(index.conflicts.first.messages).to eq [first, second]
    expect(index.message('a@example')).to equal(first)
  end

  it 'does not join messages based only on matching subjects' do
    first = build_message('a@example', subject: 'Same subject', body: 'first')
    second = build_message('b@example', subject: 'Same subject', body: 'second')

    index = described_class.new
    index.add(first)
    index.add(second)

    expect(index.root_ids).to eq ['a@example', 'b@example']
    expect(index.parent_id('a@example')).to be_nil
    expect(index.parent_id('b@example')).to be_nil
    expect(index.child_ids('a@example')).to eq []
  end

  it 'breaks a parent reference loop deterministically without hanging' do
    messages = {
      'a@example' => build_message('a@example', in_reply_to: 'c@example', references: ['c@example']),
      'b@example' => build_message('b@example', in_reply_to: 'a@example', references: ['a@example']),
      'c@example' => build_message('c@example', in_reply_to: 'b@example', references: ['b@example'])
    }

    relationships = messages.keys.permutation.map do |order|
      index = described_class.new
      order.each { |id| index.add(messages[id]) }
      [index.root_ids, index.parent_relationships]
    end

    expect(relationships.uniq).to eq([
      [
        ['a@example'],
        {
          'a@example' => ['b@example'],
          'b@example' => ['c@example'],
          'c@example' => []
        }
      ]
    ])
  end

  it 'ignores a self-reference when choosing a parent' do
    index = described_class.new
    index.add(build_message('a@example', in_reply_to: 'a@example', references: ['a@example']))

    expect(index.root_ids).to eq ['a@example']
    expect(index.parent_id('a@example')).to be_nil
    expect(index.unresolved_references).to eq({})
  end

  it 'chooses a parent deterministically when multiple In-Reply-To IDs are present' do
    common = build_message('y@example')
    common_reply = build_message(
      'c@example',
      in_reply_to: ['x@example', 'y@example'],
      references: ['a@example', 'y@example']
    )
    first_only = build_message('d@example', in_reply_to: ['x@example', 'z@example'])

    index = described_class.new
    index.add(common)
    index.add(common_reply)
    index.add(first_only)

    expect(index.parent_id('c@example')).to eq 'y@example'
    expect(index.parent_id('d@example')).to eq 'x@example'
  end

  it 'requires a Message-ID' do
    expect { described_class.new.add(Mail.new) }.to raise_error(
      ArgumentError,
      'message must have a Message-ID'
    )
  end
end
