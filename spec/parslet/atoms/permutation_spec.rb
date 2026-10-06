require 'spec_helper'

require 'timeout'

describe Parslet::Atoms::Permutation do
  include Parslet

  let(:space) { match('\s').repeat }
  let(:all_clause_names) { [:where, :order, :limit, :offset] }
  let(:clauses) do
    {
      where: str('WHERE').as(:where) >> space,
      order: str('ORDER').as(:order) >> space,
      limit: str('LIMIT').as(:limit) >> space,
      offset: str('OFFSET').as(:offset) >> space
    }
  end

  def group_with(optional_names=[])
    permutation do |group|
      all_clause_names.each do |name|
        if optional_names.include?(name)
          group.optional(name, clauses.fetch(name))
        else
          group.required(name, clauses.fetch(name))
        end
      end
    end
  end

  def input_for(names)
    names.map { |name| name.to_s.upcase }.join(' ')
  end

  [:where, :order, :limit, :offset].permutation do |names|
    it "matches the four clauses in order #{names.map(&:upcase).join(', ')}" do
      result = group_with.parse(input_for(names))

      expect(result.keys).to eq(all_clause_names)
      names.each do |name|
        expect(result[name]).to eq(name.to_s.upcase)
        expect(result[name]).to be_a(Parslet::Slice)
      end
    end
  end

  it 'omits missing optional members and keeps required members' do
    result = group_with([:limit, :offset]).
      parse('ORDER WHERE')

    expect(result).to eq(
      where: 'WHERE',
      order: 'ORDER',
      limit: nil,
      offset: nil
    )
  end

  it 'accepts the empty string when all members are optional' do
    parser = permutation do |group|
      group.optional(:a, str('a'))
      group.optional(:b, str('b'))
    end

    expect(parser.parse('')).to eq(a: nil, b: nil)
  end

  it 'keeps member slices at the position where each clause appeared' do
    group = permutation do |p|
      p.required(:where, clauses[:where])
      p.required(:limit, clauses[:limit])
    end
    result = group.parse('WHERE LIMIT')

    expect(result[:where].offset).to eq(0)
    expect(result[:limit].offset).to eq(6)
  end

  it 'backtracks when members share a prefix or one member is a prefix' do
    parser = permutation do |group|
      group.required(:short, str('a'))
      group.required(:long, str('ab'))
    end

    expect(parser.parse('aba')).to eq(short: 'a', long: 'ab')
  end

  it 'does not steal an outer alternative when the group fails' do
    group = permutation do |p|
      p.required(:a, str('a'))
    end

    expect((group | str('z')).parse('z')).to eq('z')
  end

  it 'allows an outer sequence to continue after a prefix group match' do
    group = permutation do |p|
      p.required(:a, str('a'))
    end

    expect((group >> str('b')).parse('ab')).to eq(a: 'a')
  end

  it 'reports a repeated member differently from a missing required member' do
    parser = group_with([:limit, :offset])

    duplicate = catch_failed_parse do
      parser.parse('WHERE ORDER LIMIT LIMIT')
    end
    missing = catch_failed_parse do
      parser.parse('WHERE LIMIT')
    end

    expect(duplicate.to_s).to include('Duplicate member in permutation (:limit)')
    expect(missing.to_s).to include('Missing required member in permutation')
    expect(duplicate.to_s).not_to eq(missing.to_s)
  end

  it 'reports a repeated member when the group is used as an outer prefix' do
    space = match('\s').repeat
    parser = permutation do |group|
      group.required(:a, str('a') >> space)
      group.required(:b, str('b') >> space)
    end >> str('END')

    cause = catch_failed_parse { parser.parse('a a b END') }

    expect(cause.ascii_tree).to include('Duplicate member in permutation (:a)')
  end

  it 'keeps the deepest member failure when a required member is missing' do
    parser = permutation do |group|
      group.required(:a, str('a'))
      group.required(:b, str('b'))
    end
    cause = catch_failed_parse { parser.parse('ac') }

    expect(cause.to_s).to include('Missing required member')
    expect(cause.children.first.to_s).to eq("Expected \"b\", but got \"c\" at line 1 char 2.")
  end

  it 'supports members built directly from atoms' do
    parser = described_class.new(
      str('a').required(:a),
      str('b').optional(:b)
    )

    expect(parser.parse('ba')).to eq(a: 'a', b: 'b')
  end

  it 'is also available as a statement group constructor' do
    parser = group do |members|
      members.required(:a, str('a'))
      members.optional(:b, str('b'))
    end

    expect(parser.parse('ba')).to eq(a: 'a', b: 'b')
  end

  it 'evaluates a block without a builder argument in the parser context' do
    parser = permutation do
      required(:a, str('a'))
      optional(:b, str('b'))
    end

    expect(parser.parse('ba')).to eq(a: 'a', b: 'b')
  end

  it 'works with parser rules referenced through the builder' do
    parser_class = Class.new(Parslet::Parser) do
      root(:query)
      rule(:a) { str('a') }
      rule(:b) { str('b') }
      rule(:query) do
        permutation do |members|
          members.required(:a, a)
          members.required(:b, b)
        end
      end
    end

    expect(parser_class.new.parse('ba')).to eq(a: 'a', b: 'b')
  end

  it 'accepts a required member that matches the empty string once' do
    parser = permutation do |group|
      group.required(:guard, str('a').present?)
      group.required(:value, str('a'))
    end

    expect(parser.parse('a')).to eq(guard: nil, value: 'a')
  end

  it 'does not let an optional empty match prevent a later consuming match' do
    parser = permutation do |group|
      group.optional(:maybe, str('a').maybe)
      group.required(:value, str('a'))
    end

    Timeout.timeout(2) do
      expect(parser.parse('a')).to eq(maybe: nil, value: 'a')
    end
  end

  it 'rejects duplicate member names when building the parser' do
    expect do
      described_class.new(
        described_class::Member.new(:a, str('a'), true),
        described_class::Member.new(:a, str('b'), false)
      )
    end.to raise_error(ArgumentError, /Duplicate member names/)
  end
end
