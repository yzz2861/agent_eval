# frozen_string_literal: true
require 'support'
require 'mustermann/template'
require 'mustermann/expander'

describe Mustermann::Expander do
  describe :partial_expand do
    subject(:expander) do
      Mustermann::Expander.new('/tenants/{tenant}/users/{id}{?q,lang}', type: :template)
    end

    example do
      partial = expander.partial_expand(tenant: 'acme')
      partial.should be_a(Mustermann::Template)
      partial.to_s.should be == '/tenants/acme/users/{id}{?q,lang}'
    end

    example 'two-step expansion is equivalent to one-step expansion' do
      partial = expander.partial_expand(tenant: 'acme')
      final   = partial.expand(id: 42, q: 'a/b', lang: 'en')
      full    = expander.expand(tenant: 'acme', id: 42, q: 'a/b', lang: 'en')
      final.should be == full
      final.should be == '/tenants/acme/users/42?q=a%2Fb&lang=en'
    end

    example 'the final URI is recognized by the original pattern' do
      final = expander.partial_expand(tenant: 'acme').expand(id: 42, q: 'x', lang: 'en')
      expander.patterns.first.should === final
    end

    example 'supports string keys' do
      expander.partial_expand('tenant' => 'acme').to_s.
        should be == '/tenants/acme/users/{id}{?q,lang}'
    end

    example 'raises for an invalid value at the partial stage' do
      expect { expander.partial_expand(tenant: BasicObject.new) }.
        to raise_error(Mustermann::ExpandError)
    end

    example 'raises for a missing value at the final stage' do
      expect { expander.partial_expand(tenant: 'acme').expand(id: 42, q: 'x') }.
        to raise_error(Mustermann::ExpandError, /lang|q/)
    end

    example 'is not supported for non-template patterns' do
      expect { Mustermann::Expander.new('/:a').partial_expand(a: 1) }.
        to raise_error(NotImplementedError)
    end

    example 'is not supported for several patterns' do
      expander = Mustermann::Expander.new(type: :template) << '/{a}' << '/{b}'
      expect { expander.partial_expand(a: 1) }.
        to raise_error(NotImplementedError)
    end

    example 'escapes reserved characters in appended additional values' do
      expander = Mustermann::Expander.new('/{a}', type: :template, additional_values: :append)
      expander.expand(a: 'x', path: 'a/b?c&d=e').
        should be == '/x?path=a%2Fb%3Fc%26d%3De'
    end

    context 'additional values' do
      subject(:expander) do
        Mustermann::Expander.new('/{a}{?b}', type: :template)
      end

      example 'ignores additional values' do
        expander.expand(:ignore, a: 'x', b: 'y', c: 'z').
          should be == '/x?b=y'
      end

      example 'appends additional values as query parameters' do
        expander.expand(:append, a: 'x', c: 'hello world').
          should be == '/x?c=hello%20world'
      end

      example 'raises on an unknown behavior' do
        expect { expander.expand(:bogus, a: 'x') }.
          to raise_error(ArgumentError)
      end
    end
  end
end
