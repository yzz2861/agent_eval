# frozen_string_literal: true

require 'test_helper'

include I18n::Locale

class I18nLocaleCanonicalTest < I18n::TestCase
  def canonical(aliases)
    Canonical.new(aliases)
  end

  test "returns the locale unchanged when the alias table is empty" do
    canonicalizer = canonical({})
    assert_equal :en, canonicalizer.canonical(:en)
    assert_equal :'de-DE', canonicalizer.canonical(:'de-DE')
  end

  test "replaces legacy language codes" do
    canonicalizer = canonical(language: { iw: :he, in: :id })
    assert_equal :he, canonicalizer.canonical(:iw)
    assert_equal :'id-ID', canonicalizer.canonical(:'in-ID')
  end

  test "language aliases may chain" do
    canonicalizer = canonical(language: { aa: :bb, bb: :cc })
    assert_equal :cc, canonicalizer.canonical(:aa)
  end

  test "normalizes the casing of script and region subtags" do
    canonicalizer = canonical(script: { hant: :Hant }, region: { us: :US })
    assert_equal :'zh-Hant-TW', canonicalizer.canonical(:'zh-hant-tw')
    assert_equal :'en-US', canonicalizer.canonical(:'en-us')
    assert_equal :'en-US', canonicalizer.canonical(:'en-US')
  end

  test "casing-only aliases are not treated as cycles" do
    assert_nothing_raised do
      canonical(script: { hant: :Hant })
    end
  end

  test "supports explicit whole-tag aliases" do
    canonicalizer = canonical(tag: { :'zh-TW' => :'zh-Hant-TW' })
    assert_equal :'zh-Hant-TW', canonicalizer.canonical(:'zh-TW')
    assert_equal :'zh-Hant-TW', canonicalizer.canonical(:'zh-tw')
  end

  test "whole-tag aliases take precedence over component aliases and may chain" do
    canonicalizer = canonical(
      language: { xx: :ww },
      tag: { :'xx-AA' => :'xx-BB', :'xx-BB' => :'yy-CC' }
    )
    assert_equal :'yy-CC', canonicalizer.canonical(:'xx-AA')
  end

  test "preserves extension subtags after canonicalization" do
    canonicalizer = canonical(region: { de: :DE }, tag: { :'zh-TW' => :'zh-Hant-TW' })
    assert_equal :'de-DE-u-ca-gregory', canonicalizer.canonical(:'de-de-u-ca-gregory')
    assert_equal :'zh-Hant-TW-u-ca-gregory', canonicalizer.canonical(:'zh-TW-u-ca-gregory')
  end

  test "preserves variant subtags" do
    canonicalizer = canonical(region: { at: :AT })
    assert_equal :'de-AT-1901', canonicalizer.canonical(:'de-at-1901')
  end

  test "preserves private use subtags" do
    canonicalizer = canonical({})
    assert_equal :'x-foo', canonicalizer.canonical(:'x-foo')
    assert_equal :'de-DE-x-private', canonicalizer.canonical(:'de-de-x-private')
  end

  test "returns unparsable tags unchanged" do
    canonicalizer = canonical(language: { en: :en })
    assert_equal :bogus, canonicalizer.canonical(:bogus)
    assert_equal :'x', canonicalizer.canonical(:'x')
  end

  test "accepts both String and Symbol input and returns a Symbol" do
    canonicalizer = canonical(language: { iw: :he })
    assert_equal :he, canonicalizer.canonical('iw')
    assert_equal :he, canonicalizer.canonical(:iw)
  end

  test "equivalent identifiers resolve to the same identity" do
    canonicalizer = canonical(tag: { :'zh-TW' => :'zh-Hant-TW' })
    assert_equal canonicalizer.canonical(:'zh-TW'), canonicalizer.canonical(:'zh-tw')
  end

  test "raises LocaleAliasCycle on a language cycle" do
    error = assert_raises(I18n::LocaleAliasCycle) do
      canonical(language: { aa: :bb, bb: :aa })
    end
    assert_equal :language, error.kind
    assert_match(/aa -> bb -> aa/, error.message)
  end

  test "raises LocaleAliasCycle on a region cycle" do
    assert_raises(I18n::LocaleAliasCycle) do
      canonical(region: { AA: :BB, BB: :CC, CC: :AA })
    end
  end

  test "raises LocaleAliasCycle on a whole-tag cycle" do
    assert_raises(I18n::LocaleAliasCycle) do
      canonical(tag: { :'xx-AA' => :'yy-BB', :'yy-BB' => :'xx-AA' })
    end
  end

  test "coerce wraps hashes and keeps canonicalizer instances" do
    instance = Canonical.new(language: { aa: :bb })
    assert_same instance, Canonical.coerce(instance)
    assert_instance_of Canonical, Canonical.coerce(language: { aa: :bb })
  end
end
