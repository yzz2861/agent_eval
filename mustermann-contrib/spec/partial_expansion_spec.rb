# frozen_string_literal: true
require 'support'
require 'mustermann/template'

describe Mustermann::Template do
  subject(:pattern) { Mustermann.new(template, type: :template) }

  describe '#expand_partial' do
    shared_examples 'partial expansion' do
      it 'expands known variables and keeps the rest as a template' do
        partial = pattern.expand_partial(first_stage)
        expect(partial).to be_a(described_class::PartialExpansion)
        expect(partial.to_s).to eq(stage_template)
        expect(partial.partial?).to eq(stage_template.include?('{'))
      end

      it 'can be expanded further once the remaining values arrive' do
        partial = pattern.expand_partial(first_stage)
        expect(partial.expand(second_stage)).to eq(final_link)
      end

      it 'can be expanded partially in several steps' do
        partial = pattern.expand_partial(first_stage)
        stages = second_stage.to_a
        stages.each_with_index do |(key, value), index|
          partial = index == stages.length - 1 ? partial.expand(key => value) : partial.expand_partial(key => value)
        end
        expect(partial).to eq(final_link)
      end

      it 'is identical to expanding everything at once' do
        partial = pattern.expand_partial(first_stage)
        expect(partial.expand(second_stage)).to eq(pattern.expand(final_values))
      end

      it 'produces a link the original pattern recognizes' do
        link = pattern.expand_partial(first_stage).expand(second_stage)
        expect(pattern).to match(link)
      end

      it 'supports chaining through a re-parsed template string' do
        stage = pattern.expand_partial(first_stage).to_s
        link  = Mustermann.new(stage, type: :template).expand(second_stage)
        expect(link).to eq(final_link)
      end
    end

    context 'path variables' do
      let(:template)      { '/t/{tenant}/orders/{id}' }
      let(:first_stage)   { { tenant: 'acme' } }
      let(:second_stage)  { { id: 42 } }
      let(:stage_template){ '/t/acme/orders/{id}' }
      let(:final_values)  { { tenant: 'acme', id: 42 } }
      let(:final_link)    { '/t/acme/orders/42' }
      include_examples 'partial expansion'
    end

    context 'reserved expansion (+)' do
      let(:template)      { '{+base,path}' }
      let(:first_stage)   { { base: 'a/b' } }
      let(:second_stage)  { { path: 'c/d' } }
      let(:stage_template){ 'a/b,{+path}' }
      let(:final_values)  { { base: 'a/b', path: 'c/d' } }
      let(:final_link)    { 'a/b,c/d' }
      include_examples 'partial expansion'
    end

    context 'fragment expansion (#)' do
      let(:template)      { '/p{#a,b}' }
      let(:first_stage)   { { a: 'x' } }
      let(:second_stage)  { { b: 'y' } }
      let(:stage_template){ '/p#x,{+b}' }
      let(:final_values)  { { a: 'x', b: 'y' } }
      let(:final_link)    { '/p#x,y' }
      include_examples 'partial expansion'
    end

    context 'label expansion (.)' do
      let(:template)      { '/p{.a,b}' }
      let(:first_stage)   { { a: '1' } }
      let(:second_stage)  { { b: '2' } }
      let(:stage_template){ '/p.1{.b}' }
      let(:final_values)  { { a: '1', b: '2' } }
      let(:final_link)    { '/p.1.2' }
      include_examples 'partial expansion'
    end

    context 'path segment expansion (/)' do
      let(:template)      { '/p{/a,b}' }
      let(:first_stage)   { { a: '1' } }
      let(:second_stage)  { { b: '2' } }
      let(:stage_template){ '/p/1{/b}' }
      let(:final_values)  { { a: '1', b: '2' } }
      let(:final_link)    { '/p/1/2' }
      include_examples 'partial expansion'
    end

    context 'path-style parameter expansion (;)' do
      let(:template)      { '/p{;a,b}' }
      let(:first_stage)   { { a: '1' } }
      let(:second_stage)  { { b: '' } }
      let(:stage_template){ '/p;a=1{;b}' }
      let(:final_values)  { { a: '1', b: '' } }
      let(:final_link)    { '/p;a=1;b' }
      include_examples 'partial expansion'
    end

    context 'form-style query expansion (?)' do
      let(:template)      { '/p{?q,lang}' }
      let(:first_stage)   { { q: 'hello world' } }
      let(:second_stage)  { { lang: 'en' } }
      let(:stage_template){ '/p?q=hello%20world{&lang}' }
      let(:final_values)  { { q: 'hello world', lang: 'en' } }
      let(:final_link)    { '/p?q=hello%20world&lang=en' }
      include_examples 'partial expansion'
    end

    context 'form continuation (&)' do
      let(:template)      { '/p?fixed=1{&a,b}' }
      let(:first_stage)   { { a: '1' } }
      let(:second_stage)  { { b: '2' } }
      let(:stage_template){ '/p?fixed=1&a=1{&b}' }
      let(:final_values)  { { a: '1', b: '2' } }
      let(:final_link)    { '/p?fixed=1&a=1&b=2' }
      include_examples 'partial expansion'
    end

    context 'exploded lists' do
      let(:template)      { '/p{?tags*}' }
      let(:first_stage)   { { tags: %w[ruby sinatra] } }
      let(:second_stage)  { {} }
      let(:stage_template){ '/p?tags=ruby&tags=sinatra' }
      let(:final_values)  { { tags: %w[ruby sinatra] } }
      let(:final_link)    { '/p?tags=ruby&tags=sinatra' }
      include_examples 'partial expansion'
    end

    context 'exploded path lists' do
      let(:template)      { '/p{/tags*}' }
      let(:first_stage)   { { tags: %w[a b c] } }
      let(:second_stage)  { {} }
      let(:stage_template){ '/p/a/b/c' }
      let(:final_values)  { { tags: %w[a b c] } }
      let(:final_link)    { '/p/a/b/c' }
      include_examples 'partial expansion'
    end

    context 'exploded maps' do
      let(:template)      { '/p{?filter*}' }
      let(:first_stage)   { { filter: { 'status' => 'open', 'lang' => 'en' } } }
      let(:second_stage)  { {} }
      let(:stage_template){ '/p?status=open&lang=en' }
      let(:final_values)  { { filter: { 'status' => 'open', 'lang' => 'en' } } }
      let(:final_link)    { '/p?status=open&lang=en' }
      include_examples 'partial expansion'
    end

    context 'exploded path maps' do
      let(:template)      { '/p{/filter*}' }
      let(:first_stage)   { { filter: { 'status' => 'open' } } }
      let(:second_stage)  { {} }
      let(:stage_template){ '/p/status=open' }
      let(:final_values)  { { filter: { 'status' => 'open' } } }
      let(:final_link)    { '/p/status=open' }
      include_examples 'partial expansion'
    end

    context 'combined path and query variables' do
      let(:template)      { '/t/{tenant}/{id}{?q,lang}' }
      let(:first_stage)   { { tenant: 'acme' } }
      let(:second_stage)  { { id: 42, q: 'x', lang: 'en' } }
      let(:stage_template){ '/t/acme/{id}{?q,lang}' }
      let(:final_values)  { { tenant: 'acme', id: 42, q: 'x', lang: 'en' } }
      let(:final_link)    { '/t/acme/42?q=x&lang=en' }
      include_examples 'partial expansion'

      it 'keeps the query expression untouched when only the path is known' do
        expect(pattern.expand_partial(tenant: 'acme').to_s).to eq('/t/acme/{id}{?q,lang}')
      end
    end
  end

  describe 'escaping' do
    it 'does not double-escape existing percent encodings' do
      pattern = Mustermann.new('{+path}', type: :template)
      expect(pattern.expand(path: 'a%2Fb')).to eq('a%2Fb')
      partial = pattern.expand_partial(path: 'a%2Fb c')
      expect(partial.to_s).to eq('a%2Fb%20c')
    end

    it 'escapes reserved characters for simple variables' do
      pattern = Mustermann.new('{a}', type: :template)
      expect(pattern.expand(a: 'a,b')).to eq('a%2Cb')
    end

    it 'percent-encodes non-ASCII values' do
      pattern = Mustermann.new('{a}', type: :template)
      expect(pattern.expand(a: 'café')).to eq('caf%C3%A9')
    end

    it 'handles literal percent characters' do
      pattern = Mustermann.new('{a}', type: :template)
      expect(pattern.expand(a: '100%')).to eq('100%25')
    end
  end

  describe 'errors' do
    it 'raises for unknown keys' do
      pattern = Mustermann.new('/{a}', type: :template)
      expect { pattern.expand_partial(b: 1) }.to raise_error(Mustermann::ExpandError, /cannot expand with keys/)
    end

    it 'raises when a later variable is given before an earlier one' do
      pattern = Mustermann.new('/{a}/{b}', type: :template)
      pattern = Mustermann.new('{a,b}', type: :template)
      expect { pattern.expand_partial(b: 1) }.to raise_error(Mustermann::ExpandError, /"a" is missing.*"b" was given/)
    end

    it 'allows expanding a later expression before an earlier one' do
      pattern = Mustermann.new('/{id}{?q}', type: :template)
      expect(pattern.expand_partial(q: 'x').to_s).to eq('/{id}?q=x')
    end

    it 'raises for a missing required variable at the final stage' do
      pattern = Mustermann.new('/{a}/{b}', type: :template)
      expect { pattern.expand_partial(a: 1).expand({}) }.to raise_error(Mustermann::ExpandError, /missing values/)
    end

    it 'rejects prefix modifiers for lists' do
      pattern = Mustermann.new('{a:2}', type: :template)
      expect { pattern.expand_partial(a: %w[x y]) }.to raise_error(Mustermann::ExpandError, /prefix modifier/)
    end
  end

  describe 'non-exploded lists and maps' do
    it 'expands a non-exploded list with commas' do
      pattern = Mustermann.new('/p/{tags}', type: :template)
      expect(pattern.expand(tags: %w[a b])).to eq('/p/a,b')
    end

    it 'expands a non-exploded map' do
      pattern = Mustermann.new('{m}', type: :template)
      expect(pattern.expand(m: { 'k' => 'a', 'j' => 'b' })).to eq('k,a,j,b')
    end

    it 'expands an empty array as undefined' do
      pattern = Mustermann.new('/p{?a,b}', type: :template)
      expect(pattern.expand(a: [], b: 'x')).to eq('/p?b=x')
    end

    it 'renders empty values for named operators' do
      pattern = Mustermann.new('/p{?a}', type: :template)
      expect(pattern.expand(a: '')).to eq('/p?a=')
    end
  end

  describe 'additional values' do
    it 'appends unknown values as query string with :append' do
      pattern = Mustermann.new('/p/{id}', type: :template)
      expect(pattern.expand(:append, id: 7, extra: 'x y')).to eq('/p/7?extra=x%20y')
    end

    it 'ignores unknown values during partial expansion with :ignore' do
      pattern = Mustermann.new('/p/{id}', type: :template)
      expect(pattern.expand_partial(:ignore, id: 7, extra: 'x').to_s).to eq('/p/7')
    end

    it 'ignores unknown values with :ignore' do
      pattern = Mustermann.new('/p/{id}', type: :template)
      expect(pattern.expand(:ignore, id: 7, extra: 'x')).to eq('/p/7')
    end

    it 'still requires known values with :append' do
      pattern = Mustermann.new('/p/{id}', type: :template)
      expect { pattern.expand(:append, extra: 1) }.to raise_error(Mustermann::ExpandError)
    end
  end

  describe 'value handling' do
    it 'rejects non-hash arguments' do
      pattern = Mustermann.new('/{a}', type: :template)
      expect { pattern.expand_partial(Object.new) }.to raise_error(Mustermann::ExpandError, /expected a Hash/)
    end

    it 'rejects values that cannot be stringified' do
      pattern = Mustermann.new('{a}', type: :template)
      thing = Object.new
      thing.define_singleton_method(:respond_to?) { |*| false }
      expect { pattern.expand(a: thing) }.to raise_error(Mustermann::ExpandError, /cannot use/)
    end

    it 'accepts string and symbol keys interchangeably' do
      pattern = Mustermann.new('/{a}', type: :template)
      expect(pattern.expand('a' => 1)).to eq('/1')
    end

    it 'is also reachable through Mustermann::Expander for simple templates' do
      expander = Mustermann::Expander.new('/{a}', type: :template)
      expect(expander.expand(a: 'x')).to eq('/x')
    end

    it 'has a useful inspect representation' do
      partial = Mustermann.new('/{a}', type: :template).expand_partial({})
      expect(partial.inspect).to include('PartialExpansion', '/{a}')
      expect(partial.to_pattern).to be_a(described_class)
    end

    it 'rejects unknown behavior symbols' do
      pattern = Mustermann.new('/{a}', type: :template)
      expect { pattern.expand(:bogus, a: 1) }.to raise_error(ArgumentError, /unknown behavior/)
      expect { pattern.expand_partial(:bogus, a: 1) }.to raise_error(ArgumentError, /unknown behavior/)
    end

    it 'keeps nil values as undefined in partial expansion' do
      pattern = Mustermann.new('{a,b}', type: :template)
      expect(pattern.expand_partial(a: nil).to_s).to eq('{a,b}')
    end

    it 'renders residual comma expressions without an operator' do
      pattern = Mustermann.new('{a,b}', type: :template)
      expect(pattern.expand_partial(a: '1').to_s).to eq('1,{b}')
    end

    it 'preserves non-ASCII literals' do
      pattern = Mustermann.new("/f\u00f6o/{a}", type: :template)
      expect(pattern.expand_partial(a: 'b').to_s).to eq('/f%C3%B6o/b')
    end
  end
end
