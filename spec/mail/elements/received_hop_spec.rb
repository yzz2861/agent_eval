# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::ReceivedHop do

  it "parses a standard received header into its parts" do
    hop = Mail::ReceivedHop.new('from localhost (localhost [127.0.0.1]) by xxx.xxxxx.com (Postfix) with ESMTP id 50FD3A96F for <xxxx@xxxx.com>; Tue, 10 May 2005 17:26:50 +0000 (GMT)')
    expect(hop.from).to      eq 'localhost (localhost [127.0.0.1])'
    expect(hop.by).to        eq 'xxx.xxxxx.com (Postfix)'
    expect(hop.with).to      eq 'ESMTP'
    expect(hop.id).to        eq '50FD3A96F'
    expect(hop.for).to       eq '<xxxx@xxxx.com>'
    expect(hop.date_time).to eq ::DateTime.parse('10 May 2005 17:26:50 +0000')
    expect(hop.extra).to     eq []
    expect(hop.errors).to    eq []
  end

  it "keeps the raw field value" do
    raw = 'from a.example by b.example; Tue, 10 May 2005 17:26:50 +0000'
    expect(Mail::ReceivedHop.new(raw).raw).to eq raw
  end

  it "does not treat keywords inside comments as structure" do
    hop = Mail::ReceivedHop.new('from a.example (really from b.example by c.example) by d.example with SMTP id X; Tue, 10 May 2005 17:26:50 +0000')
    expect(hop.from).to eq 'a.example (really from b.example by c.example)'
    expect(hop.by).to   eq 'd.example'
    expect(hop.id).to   eq 'X'
  end

  it "does not split the date on semicolons inside comments" do
    hop = Mail::ReceivedHop.new('by d.example (Postfix; uid 99) with ESMTP id X; Tue, 10 May 2005 17:26:50 +0000')
    expect(hop.by).to        eq 'd.example (Postfix; uid 99)'
    expect(hop.date_time).to eq ::DateTime.parse('10 May 2005 17:26:50 +0000')
  end

  it "does not treat keywords inside quoted strings as structure" do
    hop = Mail::ReceivedHop.new('from "by the way".example by d.example; Tue, 10 May 2005 17:26:50 +0000')
    expect(hop.from).to eq '"by the way".example'
    expect(hop.by).to   eq 'd.example'
  end

  it "unfolds folded headers before parsing" do
    hop = Mail::ReceivedHop.new("from a.example\r\n\tby b.example with ESMTP id X;\r\n\tTue, 10 May 2005 17:26:50 +0000")
    expect(hop.from).to      eq 'a.example'
    expect(hop.by).to        eq 'b.example'
    expect(hop.date_time).to eq ::DateTime.parse('10 May 2005 17:26:50 +0000')
  end

  it "keeps unrecognized leading fragments in extra" do
    hop = Mail::ReceivedHop.new('qmail 12345 invoked from network by b.example; Tue, 10 May 2005 17:26:50 +0000')
    expect(hop.extra).to eq %w[qmail 12345 invoked]
    expect(hop.from).to  eq 'network'
    expect(hop.by).to    eq 'b.example'
  end

  it "handles a missing date" do
    hop = Mail::ReceivedHop.new('from a.example by b.example')
    expect(hop.from).to      eq 'a.example'
    expect(hop.date_time).to be_nil
  end

  it "handles an unparsable date without raising" do
    hop = Mail::ReceivedHop.new('by a.example; not a date')
    expect(hop.by).to        eq 'a.example'
    expect(hop.date_time).to be_nil
    expect(hop.errors).not_to be_empty
  end

  it "does not raise on garbage input" do
    hop = Mail::ReceivedHop.new('""""""""""""""""')
    expect(hop.from).to      be_nil
    expect(hop.date_time).to be_nil
    expect(hop.raw).to       eq '""""""""""""""""'
  end

  it "does not raise on nil input" do
    hop = Mail::ReceivedHop.new(nil)
    expect(hop.from).to      be_nil
    expect(hop.date_time).to be_nil
    expect(hop.raw).to       eq ''
  end
end
