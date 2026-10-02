# frozen_string_literal: true
require 'support'
require 'mustermann'
require 'mustermann/failure'
require 'mustermann/identity'
begin
  require 'mustermann/template'
rescue LoadError
end

describe Mustermann::Failure do
  def explain(string, pattern, **options)
    Mustermann.new(pattern, **options).explain(string)
  end

  describe 'Mustermann::Pattern#explain' do
    it 'returns nil when the string matches' do
      expect(Mustermann.new('/:id').explain('/42')).to be_nil
    end

    it 'does not affect the regular match result' do
      pattern = Mustermann.new('/:id')
      expect(pattern).to be === '/42'
      expect(pattern).not_to be === '/42/extra'
      expect(pattern.match('/42').params).to eq('id' => '42')
    end

    it 'returns a Failure for a non matching string' do
      failure = explain('/users/abc', '/users/:id', capture: { id: :integer })
      expect(failure).to be_a(described_class)
      expect(failure.position).to eq(7)
      expect(failure.string).to eq('/users/abc')
    end

    it 'returns nil for pattern types that do not support explanations' do
      pattern = Mustermann.new(/\d+/)
      expect(pattern).not_to be === 'abc'
      expect(pattern.explain('abc')).to be_nil
    end
  end

  describe 'furthest position' do
    it 'points at the capture that violated a constraint' do
      failure = explain('/users/abc', '/users/:id', capture: { id: /\d+/ })
      expect(failure.position).to eq(7)
      expect(failure.expectations.first).to have_attributes(
        kind: :capture, name: 'id', pattern_position: 7, constraint: /\d+/
      )
    end

    it 'reports trailing characters as expected end of string' do
      failure = explain('/12/34', '/:id', capture: :integer)
      expect(failure.position).to eq(3)
      expect(failure.expectations.map(&:kind)).to eq([:end])
      expect(failure.message).to eq('expected end of string at position 3')
    end

    it 'reports a missing leading literal on empty input' do
      failure = explain('', '/:id', capture: :integer)
      expect(failure.position).to eq(0)
      expectation = failure.expectations.first
      expect(expectation).to have_attributes(kind: :literal, literal: '/', pattern_position: 0)
    end

    it 'uses character positions, not byte positions, for Unicode input' do
      failure = explain("/\u{4f60}\u{597d}xyz", "/\u{4f60}\u{597d}/:id")
      expect(failure.position).to eq(3)
      expect(failure.expectations.first.literal).to eq('/')
    end

    it 'locates capture failures after multibyte prefixes' do
      failure = explain("/\u{4f60}\u{597d}/", "/\u{4f60}\u{597d}/:id")
      expect(failure.position).to eq(4)
      expect(failure.expectations.first.kind).to eq(:capture)
      expect(failure.expectations.first.pattern_position).to eq(8)
    end

    it 'reports the mismatching literal position' do
      failure = explain('/userz/1', '/users/:id')
      expect(failure.position).to eq(5)
      expect(failure.expectations.first.literal).to eq('s')
    end
  end

  describe 'alternative and optional branches' do
    it 'merges expectations at the same furthest position across alternatives' do
      failure = explain('', '/:a|:b', capture: :integer)
      expect(failure.position).to eq(0)
      kinds = failure.expectations.map(&:kind)
      expect(kinds).to eq([:literal, :capture])
      expect(failure.expectations.map(&:name)).to eq([nil, 'b'])
    end

    it 'merges named captures reached from different branches' do
      failure = explain('/a/', '/a/:x|/a/:y')
      expect(failure.position).to eq(3)
      expect(failure.expectations.map(&:name)).to eq(['x', 'y'])
      expect(failure.expectations.map(&:pattern_position)).to eq([3, 9])
    end

    it 'does not inflate the position with a farther but abandoned branch' do
      failure = explain('/aaa/abc/mid', '/aaa/:id/end|:other', capture: { id: :integer })
      expect(failure.position).to eq(5)
      expect(failure.expectations.first.name).to eq('id')
    end

    it 'diagnoses inside an optional branch' do
      failure = explain('/x//', '/:a(/:b)?')
      expect(failure.position).to eq(3)
      expect(failure.expectations.first.name).to eq('b')
    end

    it 'is deterministic across repeated calls' do
      pattern = Mustermann.new('/a/:x|/a/:y')
      first  = pattern.explain('/a/')
      second = pattern.explain('/a/')
      expect(first.position).to eq(second.position)
      expect(first.expectations).to eq(second.expectations)
    end

    it 'dedups identical expectations' do
      failure = explain('/b', '/a|:a')
      expect(failure.expectations.size).to eq(1)
      expect(failure.expectations.first.literal).to eq('a')
    end
  end

  describe 'constraints' do
    it 'reports the capture name and symbolic constraint' do
      failure = explain('/abc', '/:id', capture: :integer)
      expectation = failure.expectations.first
      expect(expectation.kind).to eq(:capture)
      expect(expectation.name).to eq('id')
      expect(expectation.constraint).to eq(:integer)
      expect(failure.message).to include('capture "id"').and include(':integer')
    end

    it 'reports regexp constraints' do
      failure = explain('/abc', '/:id', capture: { id: /\d+/ })
      expect(failure.expectations.first.constraint).to eq(/\d+/)
    end

    it 'reports array capture constraints via the segment kind' do
      failure = explain('/images/foo.JPEG', '/images/:name.:ext', capture: { ext: %w[png jpg] })
      expect(failure.position).to eq(16)
      expect(failure.expectations.first.kind).to eq(:literal)
    end

    it 'reports an except rejection' do
      pattern = Mustermann.new('/:id', except: '/ab')
      diagnosis = Mustermann::Sinatra.new('/:id', except: '/ab').explain('/ab')
      expect(diagnosis.position).to eq(0)
      expect(diagnosis.expectations.first.kind).to eq(:excluded)
      expect(pattern).not_to be === '/ab'
    end
  end

  describe Mustermann::Failure do
    subject(:failure) { explain('/users/ab', '/users/:id', capture: { id: :integer }) }

    it 'is frozen' do
      expect(failure).to be_frozen
      expect(failure.expectations).to all(be_frozen)
    end

    it 'has a useful message and detail' do
      expect(failure.to_s).to eq(failure.message)
      expect(failure.message).to include('position 7')
      expect(failure.detail).to eq("/users/ab\n       ^")
    end

    it 'supports pattern matching keys' do
      expect(failure.expectations.first.deconstruct_keys(%i[position kind name]))
        .to eq(position: 7, kind: :capture, name: 'id')
    end
  end

  describe 'messages and inspection' do
    it 'formats literal, end, splat and inspection strings' do
      literal = explain('/b', '/a').expectations.first
      expect(literal.to_s).to eq('expected "a" at position 1')
      expect(literal.inspect).to include('kind=:literal')

      trailing = explain('/1/2', '/:a', capture: :integer)
      expect(trailing.expectations.first.to_s).to eq('expected end of string at position 2')

      splat = Mustermann::Expectation.new(position: 2, kind: :splat,
                                          pattern_position: 1, name: 's')
      expect(splat.to_s).to eq('expected splat "s" at position 2')
      expect(splat.inspect).to include('name="s"')
    end

    it 'formats a capture without a name or constraint' do
      failure = Mustermann.new('/:x/y').explain('//y')
      expect(failure.expectations.first.to_s).to eq('expected capture "x" at position 1')
      expect(failure.inspect).to include('Mustermann::Failure')
    end

    it 'joins multiple expectations into a single message' do
      failure = explain('?', '/a|:b')
      expect(failure.message).to start_with('expected one of ')
      expect(failure.to_s).to eq(failure.message)
    end

    it 'labels end of string and captures in a merged message' do
      failure = explain('/x/y/', '/:a(/:b(.:e)?)?')
      expect(failure.message).to include('end of string')
      expect(failure.expectations.map(&:kind)).to include(:literal, :end)
    end

    it 'formats excluded expectations' do
      failure = Mustermann::Sinatra.new('/:id', except: '/ab').explain('/ab')
      expect(failure.message).to include('excluded')
      expect(failure.expectations.first.inspect).to include('kind=:excluded')
    end
  end

  if defined?(Mustermann::Template)
    describe 'URI templates' do
      it 'diagnoses a failing template capture with character positions' do
        failure = Mustermann::Template.new('/users/{id}').explain('/users/ab/cd')
        expect(failure.position).to eq(9)
        expect(failure.expectations.first.kind).to eq(:end)
      end

      it 'explodes path variables during diagnosis' do
        failure = Mustermann::Template.new('{/path*}').explain('/a/b!')
        expect(failure.position).to eq(4)
        expect(failure.expectations.first.kind).to eq(:end)
      end

      it 'keeps parity for templates' do
        pattern = Mustermann::Template.new('{/a*,b}')
        expect(pattern.explain('/a/x/b/y')).to be_nil
        failure = pattern.explain('/a/x/b/y!')
        expect(failure.position).to eq(8)
      end
    end
  end

  describe 'internal behavior' do
    it 'tolerates unknown AST node types without consuming input' do
      pattern = Mustermann.new('/:x')
      explainer = Mustermann::AST.const_get(:Explainer).new(pattern)
      weird = Class.new do
        def payload = nil
      end.new
      expect(explainer.send(:analyze, weird, 2)).to eq([2])
    end

    it 'handles constraints that are regexp objects' do
      pattern = Mustermann.new('/:id', capture: { id: /[a-z]+/ })
      failure = pattern.explain('/12')
      expect(failure.position).to eq(1)
      expect(failure.expectations.first.constraint).to eq(/[a-z]+/)
    end

    it 'formats unknown expectation kinds gracefully' do
      expectation = Mustermann::Expectation.new(position: 0, kind: :mystery,
                                                pattern_position: 0)
      expect(expectation.to_s).to include('mystery')
      failure = Mustermann::Failure.new(
        pattern: Mustermann.new('/:x'), string: '/1', position: 0,
        expectations: [expectation, Mustermann::Expectation.new(position: 0, kind: :other,
                                                                       pattern_position: 1)]
      )
      expect(failure.message).to include('mystery')
    end

    it 'labels splat and excluded expectations in merged messages' do
      splat = Mustermann::Expectation.new(position: 0, kind: :splat,
                                         pattern_position: 0, name: 's')
      excluded = Mustermann::Expectation.new(position: 0, kind: :excluded,
                                             pattern_position: 0)
      failure = Mustermann::Failure.new(pattern: Mustermann.new('/x'), string: 'x',
                                        position: 0, expectations: [splat, excluded])
      expect(failure.message).to include('splat').and include('allowed')
    end
  end

  describe 'identity patterns' do
    it 'reports the first differing character' do
      failure = Mustermann.new('/foo', type: :identity).explain('/fox')
      expect(failure.position).to eq(3)
      expect(failure.expectations.first.literal).to eq('o')
    end

    it 'reports a missing character on short input' do
      failure = Mustermann.new('/foo', type: :identity).explain('/fo')
      expect(failure.position).to eq(3)
      expect(failure.expectations.first.kind).to eq(:literal)
    end

    it 'reports end of string on long input' do
      failure = Mustermann.new('/foo', type: :identity).explain('/foo/bar')
      expect(failure.position).to eq(4)
      expect(failure.expectations.first.kind).to eq(:end)
    end

    it 'handles empty unicode input' do
      failure = Mustermann.new("/\u{e9}", type: :identity).explain('')
      expect(failure.position).to eq(0)
      expect(failure.expectations.first.literal).to eq('/')
    end

    it 'returns nil on a match' do
      expect(Mustermann.new('/foo', type: :identity).explain('/foo')).to be_nil
    end
  end

  describe 'parity with regular matching' do
    patterns = [
      '/:id', '/users/:id', '/:a/:b', '/:a(/:b)?', '/:id(.:ext)?',
      '/:a|:b', '/*rest', '/:id/profile', '/u/:x(.:f)?/v/:y', '/:a-:b'
    ]
    inputs = ['', '/', '/a', '/a/b', '/a/b/c', 'abc', '/123', '/12/34',
              '/a.mp3', '/x-1', '/articles/abc.png', '/caf\u{e9}', '/v//w']
    option_sets = [
      {},
      { capture: :integer },
      { capture: { id: :integer, ext: %w[png jpg] } }
    ]

    patterns.each do |pattern|
      option_sets.each do |options|
        inputs.each do |input|
          it "explain agrees with === for #{pattern.inspect} vs #{input.inspect} (#{options})" do
            subject_pattern = Mustermann.new(pattern, **options)
            expect(subject_pattern.explain(input).nil?).to eq(subject_pattern === input)
          end
        end
      end
    end
  end
end
