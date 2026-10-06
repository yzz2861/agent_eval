require 'spec_helper'
require 'timeout'

describe Parslet::Atoms::Permutation do
  include Parslet

  let(:query_clauses) do
    permutation do |members|
      members.required :where, str('where')
      members.required :order, str('order')
      members.optional :limit, str('limit')
      members.optional :offset, str('offset')
    end
  end

  def strings(result)
    result.each_with_object({}) do |(name, value), memo|
      memo[name] = value.to_s
    end
  end

  it 'matches four named members in every permutation' do
    [:where, :order, :limit, :offset].permutation.each do |clauses|
      result = query_clauses.parse(clauses.map(&:to_s).join)

      strings(result).should == {
        where: 'where',
        order: 'order',
        limit: 'limit',
        offset: 'offset'
      }
    end
  end

  it 'omits absent optional members from the result' do
    result = query_clauses.parse('whereorder')

    strings(result).should == { where: 'where', order: 'order' }
  end

  it 'keeps the original Slice for every matched member' do
    result = query_clauses.parse('orderwherelimit')

    result[:order].should be_a(Parslet::Slice)
    result[:where].should be_a(Parslet::Slice)
    result[:limit].should be_a(Parslet::Slice)
    result[:order].offset.should == 0
    result[:where].offset.should == 5
    result[:limit].offset.should == 10
  end

  it 'reports a missing required member differently from a duplicate member' do
    missing = catch_failed_parse { query_clauses.parse('wherelimit') }
    duplicate = catch_failed_parse { query_clauses.parse('whereorderlimitlimit') }

    missing.to_s.should include('Missing required permutation member(s): [:order]')
    duplicate.to_s.should include('Duplicate permutation member(s): [:limit]')
  end

  it 'backtracks when a shorter shared prefix would consume the wrong member' do
    clauses = permutation do |members|
      members.optional :short, str('o')
      members.required :word, str('order')
    end

    result = clauses.parse('order')

    result.keys.should == [:word]
    result[:word].to_s.should == 'order'
  end

  it 'matches members that begin with the same prefix in either order' do
    clauses = permutation do |members|
      members.required :short, str('ord')
      members.required :long, str('order')
    end

    strings(clauses.parse('ordorder')).should == { short: 'ord', long: 'order' }
    strings(clauses.parse('orderord')).should == { short: 'ord', long: 'order' }
  end

  it 'allows an enclosing alternative to backtrack after the group fails' do
    parser = query_clauses | str('other')

    result = parser.parse('other')

    result.should be_a(Parslet::Slice)
    result.to_s.should == 'other'
  end

  it 'handles a member that matches the empty string without revisiting it' do
    clauses = permutation do |members|
      members.required :letter, str('a')
      members.optional :blank, str('a').absent?
      members.optional :bee, str('b')
    end

    result = clauses.parse('a')

    result.keys.should == [:letter, :blank]
    result[:letter].to_s.should == 'a'
    result[:blank].should be_nil
  end

  it 'does not loop while checking an empty match for duplication' do
    clauses = permutation do |members|
      members.required :letter, str('a')
      members.optional :blank, str('a').absent?
    end

    result = nil
    Timeout.timeout(1) do
      result = clauses.parse('a')
    end

    result.keys.should == [:letter, :blank]
  end

  it 'accepts members declared as name, parslet, required triples' do
    clauses = described_class.new([
      [:first, str('a'), true],
      [:second, str('b'), false]
    ])

    strings(clauses.parse('ba')).should == { first: 'a', second: 'b' }
  end

  it 'requires an explicit true or false required flag for constructor triples' do
    expect do
      described_class.new([[:first, str('a'), :maybe]])
    end.to raise_error(ArgumentError, 'permutation member :first must be required or optional')
  end

  it 'uses the declared order for inspection and marks optional members' do
    query_clauses.inspect.should ==
      "PERMUTATION(where:'where', order:'order', limit:'limit'?, offset:'offset'?)"
  end

  it 'is available through the group DSL alias' do
    clauses = group do |members|
      members.required :letter, str('a')
    end

    clauses.should be_a(described_class)
    strings(clauses.parse('a')).should == { letter: 'a' }
  end

  it 'exposes members to a visitor' do
    visitor = Object.new
    seen = nil
    visitor.define_singleton_method(:visit_permutation) do |members|
      seen = members
    end

    query_clauses.accept(visitor)

    seen.map(&:name).should == [:where, :order, :limit, :offset]
    seen.map(&:required).should == [true, true, false, false]
  end
end
