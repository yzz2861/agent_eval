require 'test_helper'

class VocabulariesTest < Minitest::Test
  class EvenKeyword < JSONSchemer::Keyword
    def validate(instance, instance_location, keyword_location, _context)
      valid = instance.even?
      result(
        instance,
        instance_location,
        keyword_location,
        valid,
        :annotation => { 'implementation' => 'even', 'value' => value }
      )
    end
  end

  class PositiveKeyword < JSONSchemer::Keyword
    def validate(instance, instance_location, keyword_location, _context)
      valid = instance.positive?
      result(
        instance,
        instance_location,
        keyword_location,
        valid,
        :annotation => { 'implementation' => 'positive', 'value' => value }
      )
    end
  end

  EVEN_VOCABULARY_URI = 'https://example.test/vocab/even'
  POSITIVE_VOCABULARY_URI = 'https://example.test/vocab/positive'
  MARK_VOCABULARY_URI = 'https://example.test/vocab/mark'

  CORE_VOCABULARY_URI = 'https://json-schema.org/draft/2020-12/vocab/core'

  EVEN_DIALECT_URI = URI('https://example.test/dialect/even')
  POSITIVE_DIALECT_URI = URI('https://example.test/dialect/positive')
  REMOTE_SCHEMA_URI = URI('https://example.test/schema/positive')

  def test_instance_registries_select_dialect_keywords_and_propagate_annotations
    even_vocabularies = { EVEN_VOCABULARY_URI => { 'x-even' => EvenKeyword } }
    positive_vocabularies = { POSITIVE_VOCABULARY_URI => { 'x-positive' => PositiveKeyword } }

    even_schemer = JSONSchemer.schema(
      { 'x-even' => true },
      :meta_schema => meta_schema(EVEN_DIALECT_URI, EVEN_VOCABULARY_URI, even_vocabularies),
      :vocabularies => even_vocabularies
    )
    positive_schemer = JSONSchemer.schema(
      { 'x-positive' => true },
      :meta_schema => meta_schema(POSITIVE_DIALECT_URI, POSITIVE_VOCABULARY_URI, positive_vocabularies),
      :vocabularies => positive_vocabularies
    )

    assert(even_schemer.valid?(2))
    refute(even_schemer.valid?(3))
    assert(positive_schemer.valid?(1))
    refute(positive_schemer.valid?(-1))

    even_result = even_schemer.validate(2, :output_format => 'verbose', :resolve_enumerators => true)
    assert_equal(
      { 'implementation' => 'even', 'value' => true },
      annotation(even_result, '/x-even')
    )

    positive_result = positive_schemer.validate(1, :output_format => 'verbose', :resolve_enumerators => true)
    assert_equal(
      { 'implementation' => 'positive', 'value' => true },
      annotation(positive_result, '/x-positive')
    )
  end

  def test_same_keyword_uri_uses_separate_instance_registry_implementations
    first_vocabularies = JSONSchemer::Vocabularies.new.register(MARK_VOCABULARY_URI, 'x-rule' => EvenKeyword)
    second_vocabularies = JSONSchemer::Vocabularies.new.register(MARK_VOCABULARY_URI, 'x-rule' => PositiveKeyword)

    first_meta_schema = meta_schema(URI('https://example.test/dialect/mark-one'), MARK_VOCABULARY_URI, first_vocabularies)
    second_meta_schema = meta_schema(URI('https://example.test/dialect/mark-two'), MARK_VOCABULARY_URI, second_vocabularies)

    first_schemer = JSONSchemer.schema(
      { 'x-rule' => true },
      :meta_schema => first_meta_schema,
      :vocabularies => first_vocabularies
    )
    second_schemer = JSONSchemer.schema(
      { 'x-rule' => true },
      :meta_schema => second_meta_schema,
      :vocabularies => second_vocabularies
    )

    assert_equal('even', annotation(result(first_schemer, 2), '/x-rule').fetch('implementation'))
    assert_equal('positive', annotation(result(second_schemer, 1), '/x-rule').fetch('implementation'))
  end

  def test_reference_to_another_dialect_switches_vocabulary_environment
    vocabularies = {
      EVEN_VOCABULARY_URI => { 'x-even' => EvenKeyword },
      POSITIVE_VOCABULARY_URI => { 'x-positive' => PositiveKeyword }
    }
    positive_meta_schema = meta_schema(POSITIVE_DIALECT_URI, POSITIVE_VOCABULARY_URI, vocabularies)
    positive_schema = {
      '$schema' => POSITIVE_DIALECT_URI.to_s,
      'x-positive' => true
    }
    ref_resolver = proc do |uri|
      case uri
      when POSITIVE_DIALECT_URI
        positive_meta_schema.value
      when REMOTE_SCHEMA_URI
        positive_schema
      end
    end
    even_schemer = JSONSchemer.schema(
      { '$ref' => REMOTE_SCHEMA_URI.to_s },
      :meta_schema => meta_schema(EVEN_DIALECT_URI, EVEN_VOCABULARY_URI, vocabularies),
      :vocabularies => vocabularies,
      :ref_resolver => ref_resolver
    )

    assert(even_schemer.valid?(1))
    refute(even_schemer.valid?(-1))
    assert_equal(
      { 'implementation' => 'positive', 'value' => true },
      annotation(even_schemer.validate(1, :output_format => 'basic', :resolve_enumerators => true), '/$ref/x-positive')
    )
  end

  def test_required_unregistered_vocabulary_fails_at_preparation
    error = assert_raises(JSONSchemer::UnknownVocabulary) do
      meta_schema(EVEN_DIALECT_URI, EVEN_VOCABULARY_URI)
    end
    assert_equal(EVEN_VOCABULARY_URI, error.message)

    error = assert_raises(JSONSchemer::UnknownVocabulary) do
      JSONSchemer.schema(
        { '$schema' => EVEN_DIALECT_URI.to_s, 'x-even' => true },
        :ref_resolver => proc do |uri|
          next unless uri == EVEN_DIALECT_URI
          {
            '$schema' => 'https://json-schema.org/draft/2020-12/schema',
            '$id' => EVEN_DIALECT_URI.to_s,
            '$vocabulary' => {
              CORE_VOCABULARY_URI => true,
              EVEN_VOCABULARY_URI => true
            }
          }
        end
      )
    end
    assert_equal(EVEN_VOCABULARY_URI, error.message)
  end

  def test_optional_unregistered_vocabulary_is_ignored
    optional_meta_schema = {
      '$schema' => 'https://json-schema.org/draft/2020-12/schema',
      '$id' => EVEN_DIALECT_URI.to_s,
      '$vocabulary' => {
        CORE_VOCABULARY_URI => true,
        'https://json-schema.org/draft/2020-12/vocab/validation' => true,
        EVEN_VOCABULARY_URI => false
      }
    }
    optional_meta_schemer = JSONSchemer.schema(optional_meta_schema)
    schemer = JSONSchemer.schema({ 'type' => 'integer' }, :meta_schema => optional_meta_schemer)

    assert(schemer.valid?(1))
    refute(schemer.valid?('nope'))
  end

  def test_core_keywords_cannot_be_overridden
    error = assert_raises(JSONSchemer::InvalidVocabulary) do
      JSONSchemer::Vocabularies.new(CORE_VOCABULARY_URI => { '$ref' => EvenKeyword })
    end
    assert_equal("#{CORE_VOCABULARY_URI} is a built-in vocabulary", error.message)

    error = assert_raises(JSONSchemer::InvalidVocabulary) do
      JSONSchemer::Vocabularies.new(EVEN_VOCABULARY_URI => { '$ref' => EvenKeyword })
    end
    assert_equal("vocabulary #{EVEN_VOCABULARY_URI} must not override core keyword $ref", error.message)
  end

  def test_vocabulary_keyword_implementations_must_be_keyword_classes
    error = assert_raises(JSONSchemer::InvalidVocabulary) do
      JSONSchemer::Vocabularies.new(EVEN_VOCABULARY_URI => { 'x-even' => proc {} })
    end
    assert_equal("vocabulary keyword #{EVEN_VOCABULARY_URI}#x-even must be a JSONSchemer::Keyword subclass", error.message)
  end

  def test_empty_registry_keeps_built_in_vocabularies
    vocabularies = JSONSchemer::Vocabularies.normalize(nil)

    assert(vocabularies.key?(CORE_VOCABULARY_URI))
    assert(vocabularies.fetch(CORE_VOCABULARY_URI).key?('$ref'))
  end

  private

  def meta_schema(base_uri, vocabulary_uri, vocabularies = {})
    meta_schema = {
      '$schema' => 'https://json-schema.org/draft/2020-12/schema',
      '$id' => base_uri.to_s,
      '$vocabulary' => {
        CORE_VOCABULARY_URI => true,
        vocabulary_uri => true
      }
    }
    JSONSchemer.schema(meta_schema, :vocabularies => vocabularies)
  end

  def result(schemer, instance = 1)
    schemer.validate(instance, :output_format => 'verbose', :resolve_enumerators => true)
  end

  def annotation(result, keyword_location)
    result.fetch('annotations').find do |annotation|
      annotation.fetch('keywordLocation') == keyword_location
    end.fetch('annotation')
  end
end
