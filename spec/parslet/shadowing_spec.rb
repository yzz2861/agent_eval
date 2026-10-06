require 'spec_helper'

describe Parslet::Shadowing do
  def check(atom, alphabet: %w(i f x), max_length: 3, limit: 10)
    Parslet::Shadowing.check(
      atom, alphabet: alphabet, max_length: max_length, limit: limit)
  end

  let(:keyword) { Parslet.str('if') }
  let(:identifier) { Parslet.match('[a-z]').repeat(1) }

  describe '.check' do
    it 'finds witnesses where an early branch shadows a later one' do
      report = check(keyword | identifier)

      expect(report).to be_found

      # "ifx": keyword wins with 2 characters, identifier would take 3.
      witness = report.witnesses.find { |w| w.input == 'ifx' }
      expect(witness).not_to be_nil
      expect(witness.winner.consumed).to eq 2
      expect(witness.shadowed.map(&:consumed)).to eq [3]
    end

    it 'reports different witnesses when branches are swapped' do
      report = check(identifier | keyword)

      # Now the identifier wins on "if" and the keyword is unreachable.
      witness = report.witnesses.find { |w| w.input == 'if' }
      expect(witness).not_to be_nil
      expect(witness.winner.consumed).to eq 2
      expect(witness.shadowed.map(&:consumed)).to eq [2]

      # On "ifx" the identifier wins by consuming everything; the keyword
      # (2 characters) is the shadowed branch now.
      witness = report.witnesses.find { |w| w.input == 'ifx' }
      expect(witness).not_to be_nil
      expect(witness.winner.consumed).to eq 3
      expect(witness.shadowed.map(&:consumed)).to eq [2]
    end

    it 'finds nothing for disjoint branches and says so honestly' do
      report = check(Parslet.str('a') | Parslet.str('b'), alphabet: %w(a b))

      expect(report).not_to be_found
      expect(report.to_s).to include 'does not prove'
    end

    it 'handles lookahead with real choice semantics' do
      keyword_with_boundary = keyword >> Parslet.match('[a-z]').absent?
      report = check(keyword_with_boundary | identifier)

      # "if" passes the boundary check and shadows the identifier; "ifx"
      # fails the lookahead, so the identifier wins there (no shadowing).
      expect(report.witnesses.map(&:input)).to include 'if'
      expect(report.witnesses.map(&:input)).not_to include 'ifx'
    end

    it 'handles recursive rules with real choice semantics' do
      parser = Class.new(Parslet::Parser) do
        rule(:nested) { Parslet.str('(') >> nested.maybe >> Parslet.str(')') }
        rule(:token) { nested | Parslet.str('(') }
      end

      report = check(parser.new.token, alphabet: ['(', ')'], max_length: 2)

      # "()" is parsed by the recursive rule (2 chars); the plain '('
      # branch would also match (1 char) but is never tried.
      witness = report.witnesses.find { |w| w.input == '()' }
      expect(witness).not_to be_nil
      expect(witness.winner.consumed).to eq 2
      expect(witness.shadowed.map(&:consumed)).to eq [1]
    end

    it 'stops at dynamic atoms and reports the boundary' do
      dynamic = Parslet.dynamic { Parslet.str('i') }
      report = check(dynamic | identifier)

      expect(report.boundaries.size).to eq 1
      expect(report.boundaries.first).to include 'branch 1'
      # The dynamic branch is skipped, so it can never win and never be
      # part of a witness.
      expect(report.witnesses).to be_empty
    end

    it 'verifies witnesses against the real atoms' do
      report = check(keyword | identifier)
      expect(report.verify!).to eq true
    end

    it 'rejects atoms that are not alternatives' do
      expect {
        check(Parslet.str('a'))
      }.to raise_error(ArgumentError, /alternative/)
    end

    it 'respects the witness limit' do
      report = check(keyword | identifier, max_length: 4, limit: 1)

      expect(report.witnesses.size).to eq 1
      expect(report.truncated).to eq true
    end
  end
end
