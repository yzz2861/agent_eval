# frozen_string_literal: true
require 'support'
require 'mustermann'
require 'mustermann/rails'

describe Mustermann::Pattern do
  describe :explain do
    it 'returns nil when the pattern matches' do
      expect(Mustermann::Identity.new('foo').explain('foo')).to be_nil
    end

    it 'provides a generic explanation for non-AST patterns' do
      explanation = Mustermann::Identity.new('foo').explain('bar')
      expect(explanation).to be_a(Mustermann::Explanation)
      expect(explanation.position).to be == 0
      expect(explanation.expectations.size).to be == 1
      expect(explanation.expectations.first.kind).to be == :pattern
      expect(explanation.message).to be == 'expected a string matching "foo" at position 0 in "bar"'
    end
  end
end

describe Mustermann::AST::Pattern do
  describe :explain do
    it 'returns nil when the pattern matches' do
      expect(Mustermann.new('/foo').explain('/foo')).to be_nil
    end

    it 'points at the first mismatching literal' do
      explanation = Mustermann.new('/foo').explain('/bar')
      expect(explanation.position).to be == 1
      expect(explanation.message).to be == 'expected "f" at position 1 in "/bar"'
      expectation = explanation.expectations.first
      expect(expectation.kind).to be == :literal
      expect(expectation.pattern_range).to be == (1...2)
    end

    it 'handles empty input' do
      explanation = Mustermann.new('/foo').explain('')
      expect(explanation.message).to be == 'expected "/" at position 0 in ""'
    end

    it 'describes a missing capture' do
      explanation = Mustermann.new('/users/:id').explain('/users/')
      expect(explanation.message).to be == 'expected a path segment (:id) at position 7 in "/users/"'
      expect(explanation.expectations.first.pattern_range).to be == (7...10)
    end

    it 'describes a failing capture constraint from a symbol' do
      explanation = Mustermann.new('/users/:id', capture: :digit).explain('/users/new')
      expect(explanation.message).to be == 'expected a digit segment (:id) at position 7 in "/users/new"'
      expect(explanation.expectations.first.kind).to be == :capture
    end

    it 'picks a proper article for the constraint description' do
      explanation = Mustermann.new('/users/:id', capture: :integer).explain('/users/new')
      expect(explanation.message).to be == 'expected an integer segment (:id) at position 7 in "/users/new"'
    end

    it 'describes a failing capture constraint from a hash of regexp' do
      explanation = Mustermann.new('/users/:id', capture: { id: /\d+/ }).explain('/users/new')
      expect(explanation.message).to be == 'expected a segment matching /\d+/ (:id) at position 7 in "/users/new"'
    end

    it 'describes a failing capture constraint from an array' do
      explanation = Mustermann.new('/:id', capture: %w[foo bar]).explain('/baz')
      expect(explanation.message).to be == 'expected a segment matching one of ["foo", "bar"] (:id) at position 1 in "/baz"'
    end

    it 'describes a failing capture constraint from a string' do
      explanation = Mustermann.new('/:id', capture: 'abc').explain('/ab')
      expect(explanation.message).to be == 'expected a segment matching "abc" (:id) at position 1 in "/ab"'
    end

    it 'describes a failing capture constraint from a class' do
      explanation = Mustermann.new('/:id', capture: Integer).explain('/abc')
      expect(explanation.message).to be == 'expected a segment matching /-?\d+/ (:id) at position 1 in "/abc"'
    end

    it 'points out trailing characters' do
      explanation = Mustermann.new('/:a/:b').explain('/x/y/z')
      expect(explanation.message).to be == 'expected end of input at position 4 in "/x/y/z"'
      expect(explanation.expectations.first.kind).to be == :end
      expect(explanation.matched_prefix).to be == '/x/y'
      expect(explanation.remainder).to be == '/z'
    end

    it 'merges expectations from failing optional branches at the same position' do
      explanation = Mustermann.new('/foo(/bar)?/baz').explain('/foo/baq')
      expect(explanation.position).to be == 7
      expect(explanation.expectations.map(&:description)).to be == ['"r"', '"z"']
      expect(explanation.message).to be == 'expected "r" or "z" at position 7 in "/foo/baq"'
    end

    it 'merges expectations from union branches' do
      explanation = Mustermann.new('/(a|b)').explain('/c')
      expect(explanation.message).to be == 'expected "a" or "b" at position 1 in "/c"'
    end

    it 'looks past splats' do
      explanation = Mustermann.new('/*splat/foo').explain('/a/b/bar')
      expect(explanation.message).to be == 'expected "/" at position 8 in "/a/b/bar"'
    end

    it 'does not let states ruled out by a look-ahead mislead the result' do
      # The capture cannot consume "b" here, since the look-ahead knows the
      # rest of the pattern starts there.
      explanation = Mustermann.new('/:a(b)?').explain('/b')
      expect(explanation.message).to be == 'expected a path segment (:a) at position 1 in "/b"'
    end

    it 'matches the remainder of a look-ahead node' do
      explanation = Mustermann.new('/:a(b)?/c').explain('/ab/d')
      expect(explanation.message).to be == 'expected "c" at position 4 in "/ab/d"'
    end

    it 'handles look-aheads that never trigger' do
      explanation = Mustermann.new('/:a(b)?/c').explain('/ax/d')
      expect(explanation.message).to be == 'expected "c" at position 4 in "/ax/d"'
    end

    it 'explains strings excluded via the except option' do
      explanation = Mustermann.new('/:name', except: '/admin').explain('/admin')
      expect(explanation.message).to be == 'expected a string not matching "/admin" at position 6 in "/admin"'
      expect(explanation.expectations.first.kind).to be == :except
    end

    it 'locates mismatches in unicode patterns' do
      explanation = Mustermann.new('/föö').explain('/fx')
      expect(explanation.message).to be == 'expected "ö" at position 2 in "/fx"'
    end

    it 'locates mismatches after unicode input' do
      explanation = Mustermann.new('/:a/x').explain('/ä/y')
      expect(explanation.message).to be == 'expected "x" at position 3 in "/ä/y"'
      expect(explanation.matched_prefix).to be == '/ä/'
    end

    it 'locates mismatches after URI-encoded input' do
      explanation = Mustermann.new('/fö').explain('/f%C3%B6x')
      expect(explanation.message).to be == 'expected end of input at position 8 in "/f%C3%B6x"'
    end

    it 'honors the uri_decode option' do
      explanation = Mustermann.new('/f o', uri_decode: false).explain('/f+o')
      expect(explanation.message).to be == 'expected " " at position 2 in "/f+o"'
    end

    it 'works with rails patterns' do
      explanation = Mustermann.new('/:id', type: :rails, capture: :digit).explain('/abc')
      expect(explanation.message).to be == 'expected a digit segment (:id) at position 1 in "/abc"'
    end

    it 'produces stable diagnostics for ambiguous patterns' do
      pattern = Mustermann.new('/foo(/bar)?/baz')
      first, second = pattern.explain('/foo/baq'), pattern.explain('/foo/baq')
      expect(first.message).to be == second.message
      expect(first.expectations).to be == second.expectations
    end

    it 'keeps the matching verdict of the regular API' do
      pattern = Mustermann.new('/:a(b)?')
      expect(pattern.match('/ab').params).to be == { 'a' => 'a' }
      expect(pattern.explain('/ab')).to be_nil
      expect(pattern.explain('/b')).not_to be_nil
    end
  end
end

describe Mustermann::AST::Explainer do
  def fake_pattern(ast)
    Struct.new(:to_ast, :options) do
      def except_regexp(*) = nil
    end.new(ast, {})
  end

  def root_with(node)
    Mustermann::AST::Node::Root.new([node])
  end

  it 'treats or nodes like unions' do
    or_node = Mustermann::AST::Node::Or.new([
      Mustermann::AST::Node::Char.new('a'),
      Mustermann::AST::Node::Char.new('b')
    ])
    explanation = described_class.explain(fake_pattern(root_with(or_node)), 'c')
    expect(explanation.message).to be == 'expected "a" or "b" at position 0 in "c"'
  end

  it 'raises a CompileError for nodes it cannot explain' do
    stub_const('Mustermann::AST::Node::Mystery', Class.new(Mustermann::AST::Node))
    node = Mustermann::AST::Node::Mystery.new
    expect { described_class.explain(fake_pattern(root_with(node)), 'x') }.
      to raise_error(Mustermann::CompileError, 'cannot explain :mystery node')
  end

  it 'describes a failing splat with a constraint' do
    splat = Mustermann::AST::Node::Splat.new(nil, constraint: '\d+')
    explanation = described_class.explain(fake_pattern(root_with(splat)), 'abc')
    expect(explanation.message).to be == 'expected a splat at position 0 in "abc"'
  end

  it 'describes a failing named splat with a constraint' do
    splat = Mustermann::AST::Node::NamedSplat.new('rest', constraint: '\d+')
    explanation = described_class.explain(fake_pattern(root_with(splat)), 'abc')
    expect(explanation.message).to be == 'expected a splat (*rest) at position 0 in "abc"'
  end

  it 'describes a failing capture with a constraint' do
    capture = Mustermann::AST::Node::Capture.new('id', constraint: /\d+/)
    explanation = described_class.explain(fake_pattern(root_with(capture)), 'abc')
    expect(explanation.message).to be == 'expected a segment matching /\d+/ (:id) at position 0 in "abc"'
  end
end

describe Mustermann::Explanation do
  subject(:explanation) do
    described_class.new(pattern: Mustermann.new('/foo'), string: '/bar',
                        position: 1, expectations: [Mustermann::Explanation::Expectation.new(:literal, detail: 'f')])
  end

  it 'has a human readable message' do
    expect(explanation.message).to be == 'expected "f" at position 1 in "/bar"'
    expect(explanation.to_s).to be == explanation.message
  end

  it 'exposes pattern, string, position and expectations' do
    expect(explanation.pattern).to be == Mustermann.new('/foo')
    expect(explanation.string).to be == '/bar'
    expect(explanation.position).to be == 1
    expect(explanation.expectations.size).to be == 1
  end

  it 'splits the string at the failure position' do
    expect(explanation.matched_prefix).to be == '/'
    expect(explanation.remainder).to be == 'bar'
  end

  it 'has a readable inspect' do
    expect(explanation.inspect).to be == '#<Mustermann::Explanation: expected "f" at position 1 in "/bar">'
  end
end

describe Mustermann::Explanation::Expectation do
  it 'compares expectations by kind, name and detail' do
    one   = described_class.new(:literal, detail: 'x', pattern_range: 1...2)
    two   = described_class.new(:literal, detail: 'x', pattern_range: 5...6)
    other = described_class.new(:literal, detail: 'y', pattern_range: 1...2)
    expect(one).to be == two
    expect(one).to be_eql(two)
    expect(one.hash).to be == two.hash
    expect(one).not_to be == other
    expect(one).not_to be == 'x'
  end

  it 'exposes kind, name, detail and pattern_range' do
    expectation = described_class.new(:capture, name: 'id', detail: :digit, pattern_range: 1...4)
    expect(expectation.kind).to be == :capture
    expect(expectation.name).to be == 'id'
    expect(expectation.detail).to be == :digit
    expect(expectation.pattern_range).to be == (1...4)
    expect(expectation.description).to be == 'a digit segment (:id)'
  end

  it 'has a readable inspect' do
    expectation = described_class.new(:end)
    expect(expectation.inspect).to be == '#<Mustermann::Explanation::Expectation end of input>'
  end
end
