# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::ReceivedChain do

  it "keeps hops in header order" do
    chain = Mail::ReceivedChain.new([
      'by a.example with ESMTP id 1; Tue, 10 May 2005 17:26:50 +0000',
      'by b.example with ESMTP id 2; Tue, 10 May 2005 17:20:00 +0000'
    ])
    expect(chain.hops.map(&:by)).to eq ['a.example', 'b.example']
    expect(chain.map(&:by)).to      eq ['a.example', 'b.example']
  end

  it "does not reorder hops when a clock goes backwards" do
    chain = Mail::ReceivedChain.new([
      'by a.example with ESMTP id 1; Tue, 10 May 2005 17:20:00 +0000',
      'by b.example with ESMTP id 2; Tue, 10 May 2005 17:26:50 +0000'
    ])
    expect(chain.hops.map(&:by)).to eq ['a.example', 'b.example']
  end

  it "estimates the delay between adjacent hops" do
    chain = Mail::ReceivedChain.new([
      'by a.example with ESMTP id 1; Tue, 10 May 2005 17:26:50 +0000',
      'by b.example with ESMTP id 2; Tue, 10 May 2005 17:20:00 +0000'
    ])
    delay = chain.delays.first
    expect(delay.seconds).to      eq 410.0
    expect(delay.negative?).to    be false
    expect(delay.missing_time?).to be false
    expect(delay.hop.by).to        eq 'a.example'
    expect(delay.previous_hop.by).to eq 'b.example'
  end

  it "flags negative delays" do
    chain = Mail::ReceivedChain.new([
      'by a.example with ESMTP id 1; Tue, 10 May 2005 17:20:00 +0000',
      'by b.example with ESMTP id 2; Tue, 10 May 2005 17:26:50 +0000'
    ])
    delay = chain.delays.first
    expect(delay.seconds).to   eq(-410.0)
    expect(delay.negative?).to be true
  end

  it "flags delays where a hop is missing a usable timestamp" do
    chain = Mail::ReceivedChain.new([
      'by a.example with ESMTP id 1; not a date',
      'by b.example with ESMTP id 2; Tue, 10 May 2005 17:26:50 +0000'
    ])
    delay = chain.delays.first
    expect(delay.seconds).to       be_nil
    expect(delay.missing_time?).to be true
    expect(delay.negative?).to     be false
  end

  it "keeps the other hops when one hop fails to parse" do
    chain = Mail::ReceivedChain.new([
      'by a.example with ESMTP id 1; Tue, 10 May 2005 17:26:50 +0000',
      '""""""""""""""""',
      'by b.example with ESMTP id 2; Tue, 10 May 2005 17:20:00 +0000'
    ])
    expect(chain.hops.length).to eq 3
    expect(chain.hops[0].by).to  eq 'a.example'
    expect(chain.hops[2].by).to  eq 'b.example'
    expect(chain.hops[1].raw).to eq '""""""""""""""""'
  end

  it "accepts ReceivedHop instances" do
    hop = Mail::ReceivedHop.new('by a.example; Tue, 10 May 2005 17:26:50 +0000')
    chain = Mail::ReceivedChain.new([hop])
    expect(chain.hops).to eq [hop]
  end

  it "handles an empty chain" do
    chain = Mail::ReceivedChain.new
    expect(chain.hops).to   eq []
    expect(chain.delays).to eq []
  end
end
