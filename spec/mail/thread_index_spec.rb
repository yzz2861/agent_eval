# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::ThreadIndex do
  def build_message(id, references: [], in_reply_to: nil, subject: nil, body: nil)
    mail = Mail.new
    mail.message_id = id
    mail.subject = subject || 'Re: support ticket'
    mail.body = body || ('body of ' + id.to_s)
    mail.references = references.map { |ref| "<#{ref}>" } unless references.empty?
    mail.in_reply_to = "<#{in_reply_to}>" if in_reply_to
    mail
  end

  def conversation
    [
      build_message('a@x', subject: 'help', body: 'first'),
      build_message('b@x', references: %w[a@x], in_reply_to: 'a@x', body: 'reply 1'),
      build_message('c@x', references: %w[a@x b@x], in_reply_to: 'b@x', body: 'reply 2'),
      build_message('d@x', in_reply_to: 'a@x', body: 'another reply to root'),
      build_message('e@x', references: %w[a@x b@x c@x], in_reply_to: 'c@x', body: 'reply 3'),
    ]
  end

  describe 'threading by References and In-Reply-To' do
    it 'links children to their parents' do
      index = described_class.new
      index.add_all(conversation)

      expect(index.roots).to eq(%w[a@x])
      expect(index.parent_of('b@x')).to eq('a@x')
      expect(index.parent_of('c@x')).to eq('b@x')
      expect(index.parent_of('d@x')).to eq('a@x')
      expect(index.parent_of('e@x')).to eq('c@x')
      expect(index.children_of('a@x')).to eq(%w[b@x d@x])
      expect(index.children_of('c@x')).to eq(%w[e@x])
      expect(index.children_of('e@x')).to eq([])
    end

    it 'prefers In-Reply-To over the last References entry when they disagree' do
      index = described_class.new
      index.add(build_message('m@x', references: %w[r1@x r2@x], in_reply_to: 'r3@x'))

      expect(index.parent_of('m@x')).to eq('r3@x')
      expect(index.children_of('r3@x')).to eq(%w[m@x])
      expect(index.children_of('r2@x')).to eq([])
    end

    it 'falls back to the last References entry without In-Reply-To' do
      index = described_class.new
      index.add(build_message('m@x', references: %w[r1@x r2@x]))

      expect(index.parent_of('m@x')).to eq('r2@x')
      expect(index.parent_of('r2@x')).to eq('r1@x')
    end

    it 'does not thread messages that only share a subject' do
      index = described_class.new
      index.add(build_message('one@x', subject: 'identical subject'))
      index.add(build_message('two@x', subject: 'identical subject'))

      expect(index.roots).to eq(%w[one@x two@x])
      expect(index.parent_of('two@x')).to be_nil
    end

    it 'raises for messages without a Message-ID' do
      index = described_class.new
      expect { index.add(Mail.new) }.to raise_error(ArgumentError)
    end
  end

  describe 'placeholders and merging' do
    it 'keeps placeholders for ancestors that have not arrived' do
      index = described_class.new
      index.add(build_message('c@x', references: %w[a@x b@x], in_reply_to: 'b@x'))

      expect(index.unresolved_references).to eq(%w[a@x b@x])
      expect(index.placeholder?('b@x')).to be(true)
      expect(index.roots).to eq(%w[a@x])
      expect(index.parent_of('c@x')).to eq('b@x')
      expect(index.parent_of('b@x')).to eq('a@x')
    end

    it 'merges the real message into its placeholder once it arrives' do
      index = described_class.new
      index.add(build_message('c@x', references: %w[a@x b@x], in_reply_to: 'b@x'))
      index.add(build_message('b@x', references: %w[a@x], in_reply_to: 'a@x'))

      expect(index.unresolved_references).to eq(%w[a@x])
      expect(index.placeholder?('b@x')).to be(false)
      expect(index.message_for('b@x')).to be_a(Mail::Message)
      expect(index.children_of('b@x')).to eq(%w[c@x])
      expect(index.parent_of('b@x')).to eq('a@x')
    end

    it 'lets direct headers of a late arrival replace inferred chain links' do
      index = described_class.new
      # First message implies ghost-1 -> ghost-2 -> m.
      index.add(build_message('m@x', references: %w[ghost-1@x ghost-2@x]))
      expect(index.parent_of('ghost-2@x')).to eq('ghost-1@x')
      # The real ghost-2 says its parent is somewhere else entirely.
      index.add(build_message('ghost-2@x', in_reply_to: 'real-parent@x'))

      expect(index.parent_of('ghost-2@x')).to eq('real-parent@x')
      expect(index.children_of('ghost-1@x')).to eq([])
    end
  end

  describe 'conflict detection' do
    it 'reports same Message-ID with different content as a conflict' do
      index = described_class.new
      index.add(build_message('dup@x', body: 'original'))
      index.add(build_message('dup@x', body: 'tampered'))

      expect(index.size).to eq(1)
      expect(index.conflicts.size).to eq(1)
      conflict = index.conflicts.first
      expect(conflict.message_id).to eq('dup@x')
      expect(conflict.rejected_message.body.decoded).to eq('tampered')
      expect(index.message_for('dup@x').body.decoded).to eq('original')
    end

    it 'ignores identical duplicates silently' do
      index = described_class.new
      index.add(build_message('dup@x', body: 'same'))
      index.add(build_message('dup@x', body: 'same'))

      expect(index.size).to eq(1)
      expect(index.conflicts).to be_empty
    end
  end

  describe 'reference cycles' do
    it 'breaks cycles deterministically and never hangs traversal' do
      messages = [
        build_message('a@x', in_reply_to: 'b@x'),
        build_message('b@x', in_reply_to: 'a@x'),
      ]
      structures = [messages, messages.reverse].map do |order|
        index = described_class.new
        index.add_all(order)
        [index.roots, index.parent_of('a@x'), index.parent_of('b@x')]
      end

      expect(structures.first).to eq(structures.last)
      # The lexicographically smallest id in the cycle becomes the root.
      expect(structures.first).to eq([%w[a@x], nil, 'a@x'])

      index = described_class.new
      index.add_all(messages)
      expect(index.thread_ids('a@x')).to contain_exactly('a@x', 'b@x')
      expect(index.root_of('b@x')).to eq('a@x')
    end
  end

  describe 'arrival order independence' do
    it 'produces the same forest for every permutation of the conversation' do
      expected = nil
      conversation.permutation do |order|
        index = described_class.new
        index.add_all(order)
        structure = [
          index.roots,
          conversation.map { |m| [m.message_id, index.parent_of(m.message_id)] }.to_h,
          conversation.map { |m| [m.message_id, index.children_of(m.message_id)] }.to_h,
          index.unresolved_references,
        ]
        expected ||= structure
        expect(structure).to eq(expected)
      end
    end

    it 'produces the same forest when an ancestor is permanently missing' do
      messages = [
        build_message('p1@x', references: %w[ghost@x], in_reply_to: 'ghost@x'),
        build_message('p2@x', references: %w[ghost@x p1@x], in_reply_to: 'p1@x'),
        build_message('p3@x', in_reply_to: 'ghost@x'),
      ]
      expected = nil
      messages.permutation do |order|
        index = described_class.new
        index.add_all(order)
        structure = [
          index.roots,
          %w[ghost@x p1@x p2@x p3@x].map { |id| [id, index.parent_of(id)] }.to_h,
          index.unresolved_references,
        ]
        expected ||= structure
        expect(structure).to eq(expected)
      end

      expect(expected[0]).to eq(%w[ghost@x])
      expect(expected[2]).to eq(%w[ghost@x])
    end
  end
end

