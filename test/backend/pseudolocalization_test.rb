require 'test_helper'

class I18nBackendPseudolocalizationTest < I18n::TestCase
  def setup
    super
    I18n.backend = pseudolocalization_backend_class.new
    I18n::Backend::Pseudolocalization.reset_configuration!

    I18n.default_locale = :en
    store_translations(:en,
      message: 'Hello, world!',
      interpolation: 'Hello %{name}, score %10.2f %<named>s and 100%% complete',
      html: '<a href="https://example.com/x?a=1&amp;b=2">Hello &amp; welcome</a>',
      values: ['One', { label: 'Two' }],
      namespace: {
        title: 'Nested title',
        items: ['First', 'Second']
      },
      plural: {
        one: '%{count} item',
        other: '%{count} items'
      }
    )
    store_translations(:de, message: 'Tschüss')
  end

  def teardown
    I18n::Backend::Pseudolocalization.reset_configuration!
    super
  end

  test 'pseudo locale widens text deterministically' do
    first = I18n.t(:message, locale: :pseudo)
    second = I18n.t(:message, locale: :pseudo)

    assert_equal first, second
    assert_operator first.length, :>, I18n.t(:message, locale: :en).length
    assert_match(/\A\[.*~+\]\z/, first)
  end

  test 'configured seed changes replacement output' do
    alphabet = ('a'..'z').to_a.join * 3
    store_translations(:en, alphabet: alphabet)

    I18n::Backend::Pseudolocalization.random_seed = 1
    first = I18n.t(:alphabet, locale: :pseudo)
    I18n::Backend::Pseudolocalization.random_seed = 2
    second = I18n.t(:alphabet, locale: :pseudo)

    refute_equal first, second
  end

  test 'same transformer input is repeatable' do
    transformer = I18n::Backend::Pseudolocalization::Transformer.new(random_seed: 7)

    assert_equal transformer.transform('Repeatable'), transformer.transform('Repeatable')
  end

  test 'configured expansion ratio controls filler width' do
    I18n::Backend::Pseudolocalization.expansion_ratio = 1.0

    assert_equal 10, I18n.t(:message, locale: :pseudo).count('~')
  end

  test 'preserves interpolation placeholders, width formats, and escaped percents before interpolation' do
    result = I18n.t(:interpolation, locale: :pseudo, name: 'World', named: 'X')

    assert_includes result, 'World'
    assert_includes result, '%10.2f'
    assert_includes result, 'X'
    assert_includes result, '100%'
    refute_includes result, '%{name}'
  end

  test 'preserves escaped percents before interpolation runs' do
    result = I18n.t(:interpolation, locale: :pseudo, skip_interpolation: true)

    assert_includes result, '100%%'
    assert_includes result, '%{name}'
  end

  test 'html mode preserves tags, attributes, and entities' do
    I18n::Backend::Pseudolocalization.html = true

    result = I18n.t(:html, locale: :pseudo)

    assert_includes result, '<a href="https://example.com/x?a=1&amp;b=2">'
    assert_includes result, '&amp;'
    assert(result.start_with?('[<a'))
    assert(result.end_with?('</a>~~~~]'))
  end

  test 'html tags are transformed when html mode is disabled' do
    result = I18n.t(:html, locale: :pseudo)

    refute_includes result, 'example.com'
  end

  test 'pseudo queries do not mutate stored translations' do
    I18n.t(:message, locale: :pseudo)
    I18n.t(:namespace, locale: :pseudo)

    assert_equal 'Hello, world!', I18n.t(:message, locale: :en)
    assert_equal 'Nested title', I18n.t(:'namespace.title', locale: :en)
  end

  test 'memoized pseudo lookups do not replace ordinary lookups' do
    assert_match(/\A\[.*~+\]\z/, I18n.t(:message, locale: :pseudo))
    assert_equal 'Hello, world!', I18n.t(:message, locale: :en)
  end

  test 'arrays and nested namespaces keep their shape' do
    result = I18n.t(:values, locale: :pseudo)

    assert_kind_of Array, result
    assert_kind_of Hash, result.last
    assert_equal [:label], result.last.keys
    assert result.first.start_with?('[')
    assert result.last[:label].start_with?('[')

    namespace = I18n.t(:namespace, locale: :pseudo)
    assert_kind_of Array, namespace[:items]
    assert namespace[:title].start_with?('[')
  end

  test 'prefixed pseudo locale uses its prefix as source locale' do
    result = I18n.t(:message, locale: :'de-pseudo')

    assert_includes result, 'ü'
    assert_includes result, '~'
    assert_equal(:de, I18n.backend.send(:pseudo_source_locale, :'de-pseudo'))
  end

  test 'pseudo option transforms any locale' do
    result = I18n.t(:message, locale: :de, pseudo: true)

    assert_operator result.length, :>, I18n.t(:message, locale: :de).length
  end

  test 'pluralization still works after pseudolocalization' do
    result = I18n.t(:plural, locale: :pseudo, count: 2)

    assert_includes result, '2'
    assert_includes result, '~'
  end

  private

  def pseudolocalization_backend_class
    Class.new(I18n::Backend::Simple) do
      include I18n::Backend::Memoize
      include I18n::Backend::Pseudolocalization
    end
  end
end
