require 'test_helper'

class VocabularyTest < Minitest::Test
  STRING_CASE_VOCABULARY = 'tag:json-schemer-test,2026:vocab/string-case'
  TRUSTED_KEYS_VOCABULARY = 'tag:json-schemer-test,2026:vocab/trusted-keys'

  CORE_VOCABULARY = 'https://json-schema.org/draft/2020-12/vocab/core'
  APPLICATOR_VOCABULARY = 'https://json-schema.org/draft/2020-12/vocab/applicator'
  VALIDATION_VOCABULARY = 'https://json-schema.org/draft/2020-12/vocab/validation'

  class StringCase < JSONSchemer::Keyword
    def error(formatted_instance_location:, **)
      "value at #{formatted_instance_location} is not #{value} case"
    end

    def validate(instance, instance_location, keyword_location, _context)
      return unless instance.is_a?(String)
      valid = value == 'upper' ? instance == instance.upcase : instance == instance.downcase
      result(instance, instance_location, keyword_location, valid, :annotation => value)
    end
  end

  class UpperCase < JSONSchemer::Keyword
    def validate(instance, instance_location, keyword_location, _context)
      result(instance, instance_location, keyword_location, !instance.is_a?(String) || instance == instance.upcase)
    end
  end

  class LowerCase < JSONSchemer::Keyword
    def validate(instance, instance_location, keyword_location, _context)
      result(instance, instance_location, keyword_location, !instance.is_a?(String) || instance == instance.downcase)
    end
  end

  class TrustedKeys < JSONSchemer::Keyword
    def validate(instance, instance_location, keyword_location, _context)
      return unless instance.is_a?(Hash)
      result(instance, instance_location, keyword_location, true, :annotation => (value & instance.keys))
    end
  end

  class RejectUntrusted < JSONSchemer::Keyword
    def error(formatted_instance_location:, **)
      "value at #{formatted_instance_location} has untrusted keys"
    end

    def validate(instance, instance_location, keyword_location, context)
      return unless value && instance.is_a?(Hash)
      trusted = context.adjacent_results[TrustedKeys]&.annotation || []
      untrusted = instance.keys - trusted
      result(instance, instance_location, keyword_location, untrusted.empty?, :details => { 'untrusted_keys' => untrusted })
    end
  end

  def meta_schema_hash(*vocabulary_uris)
    {
      '$schema' => 'https://json-schema.org/draft/2020-12/schema',
      '$id' => 'https://example.com/meta/custom',
      '$vocabulary' => {
        CORE_VOCABULARY => true,
        APPLICATOR_VOCABULARY => true,
        VALIDATION_VOCABULARY => true
      }.merge(vocabulary_uris.to_h { |uri| [uri, true] }),
      'type' => ['object', 'boolean']
    }
  end

  def string_case_meta_schema(**options)
    JSONSchemer.schema(
      meta_schema_hash(STRING_CASE_VOCABULARY),
      :vocabularies => { STRING_CASE_VOCABULARY => { 'stringCase' => StringCase } },
      **options
    )
  end

  def trusted_keys_meta_schema(**options)
    JSONSchemer.schema(
      meta_schema_hash(TRUSTED_KEYS_VOCABULARY),
      :vocabularies => {
        TRUSTED_KEYS_VOCABULARY => {
          'trustedKeys' => TrustedKeys,
          'rejectUntrusted' => RejectUntrusted
        }
      },
      **options
    )
  end

  def test_vocabulary_keyword_validation
    meta_schema = string_case_meta_schema
    schemer = JSONSchemer.schema({ 'stringCase' => 'upper' }, :meta_schema => meta_schema)

    assert(schemer.valid?('ABC'))
    refute(schemer.valid?('abc'))
    assert(schemer.valid?(123))

    error = schemer.validate('abc').first
    assert_equal('stringCase', error.fetch('type'))
    assert_equal('value at root is not upper case', error.fetch('error'))

    lower_schemer = JSONSchemer.schema({ 'stringCase' => 'lower' }, :meta_schema => meta_schema)
    assert(lower_schemer.valid?('abc'))
    refute(lower_schemer.valid?('ABC'))
  end

  def test_vocabulary_keyword_annotation_in_output
    schemer = JSONSchemer.schema(
      { 'stringCase' => 'upper' },
      :meta_schema => string_case_meta_schema
    )
    output = schemer.validate('ABC', :output_format => 'basic', :resolve_enumerators => true)

    assert(output.fetch('valid'))
    annotations = output.fetch('annotations')
    assert_equal(1, annotations.size)
    assert_equal('upper', annotations.first.fetch('annotation'))
    assert_equal('/stringCase', annotations.first.fetch('keywordLocation'))
  end

  def test_vocabulary_annotation_protocol_between_keywords
    meta_schema = trusted_keys_meta_schema
    schemer = JSONSchemer.schema(
      { 'trustedKeys' => ['a'], 'rejectUntrusted' => true },
      :meta_schema => meta_schema
    )

    assert(schemer.valid?({ 'a' => 1 }))
    refute(schemer.valid?({ 'a' => 1, 'b' => 2 }))
    assert(schemer.valid?('not-an-object'))

    error = schemer.validate({ 'a' => 1, 'b' => 2 }).first
    assert_equal('value at root has untrusted keys', error.fetch('error'))
    assert_equal({ 'untrusted_keys' => ['b'] }, error.fetch('details'))

    output = schemer.validate({ 'a' => 1 }, :output_format => 'basic', :resolve_enumerators => true)
    trusted_keys_annotation = output.fetch('annotations').find { |unit| unit.fetch('keywordLocation') == '/trustedKeys' }
    assert_equal(['a'], trusted_keys_annotation.fetch('annotation'))

    disabled = JSONSchemer.schema({ 'rejectUntrusted' => false }, :meta_schema => meta_schema)
    assert(disabled.valid?({ 'b' => 1 }))

    without_trusted_keys = JSONSchemer.schema({ 'rejectUntrusted' => true }, :meta_schema => meta_schema)
    refute(without_trusted_keys.valid?({ 'b' => 1 }))
    assert(without_trusted_keys.valid?({}))
  end

  def test_required_vocabulary_must_be_registered
    error = assert_raises(JSONSchemer::UnknownVocabulary) do
      JSONSchemer.schema(meta_schema_hash(STRING_CASE_VOCABULARY))
    end
    assert_equal(STRING_CASE_VOCABULARY, error.message)
  end

  def test_optional_vocabulary_may_be_unregistered
    meta_schema = JSONSchemer.schema(
      meta_schema_hash.tap do |meta_schema|
        meta_schema['$vocabulary'][STRING_CASE_VOCABULARY] = false
      end
    )
    schemer = JSONSchemer.schema({ 'stringCase' => 'upper' }, :meta_schema => meta_schema)
    assert(schemer.valid?('abc'))
  end

  def test_vocabulary_registration_is_instance_scoped
    string_case_meta_schema
    refute(JSONSchemer::VOCABULARIES.key?(STRING_CASE_VOCABULARY))
    assert_raises(JSONSchemer::UnknownVocabulary) do
      JSONSchemer.schema(meta_schema_hash(STRING_CASE_VOCABULARY))
    end
  end

  def test_same_vocabulary_uri_with_different_implementations
    upper_meta_schema = JSONSchemer.schema(
      meta_schema_hash(STRING_CASE_VOCABULARY),
      :vocabularies => { STRING_CASE_VOCABULARY => { 'stringCase' => UpperCase } }
    )
    lower_meta_schema = JSONSchemer.schema(
      meta_schema_hash(STRING_CASE_VOCABULARY),
      :vocabularies => { STRING_CASE_VOCABULARY => { 'stringCase' => LowerCase } }
    )

    upper_schemer = JSONSchemer.schema({ 'stringCase' => true }, :meta_schema => upper_meta_schema)
    lower_schemer = JSONSchemer.schema({ 'stringCase' => true }, :meta_schema => lower_meta_schema)

    assert(upper_schemer.valid?('ABC'))
    refute(upper_schemer.valid?('abc'))
    assert(upper_schemer.valid?(123))
    assert(lower_schemer.valid?('abc'))
    refute(lower_schemer.valid?('ABC'))
    assert(lower_schemer.valid?(123))
  end

  def test_vocabulary_cannot_redefine_core_keywords
    error = assert_raises(JSONSchemer::VocabularyKeywordConflict) do
      JSONSchemer.schema(
        meta_schema_hash(STRING_CASE_VOCABULARY),
        :vocabularies => { STRING_CASE_VOCABULARY => { 'type' => StringCase } }
      )
    end
    assert_includes(error.message, 'type')
    assert_includes(error.message, STRING_CASE_VOCABULARY)
  end

  def test_vocabulary_cannot_redefine_core_keywords_through_core_uri
    assert_raises(JSONSchemer::VocabularyKeywordConflict) do
      JSONSchemer.schema(
        meta_schema_hash,
        :vocabularies => { CORE_VOCABULARY => { 'type' => StringCase } }
      )
    end
  end

  def test_vocabularies_cannot_redefine_each_others_keywords
    assert_raises(JSONSchemer::VocabularyKeywordConflict) do
      JSONSchemer.schema(
        meta_schema_hash(STRING_CASE_VOCABULARY, TRUSTED_KEYS_VOCABULARY),
        :vocabularies => {
          STRING_CASE_VOCABULARY => { 'stringCase' => StringCase },
          TRUSTED_KEYS_VOCABULARY => { 'stringCase' => UpperCase }
        }
      )
    end
  end

  def test_cross_dialect_ref_switches_vocabulary
    meta_schema = meta_schema_hash(STRING_CASE_VOCABULARY)
    schemer = JSONSchemer.schema(
      {
        'properties' => {
          'name' => { '$ref' => 'https://example.com/schemas/shouted-name' },
          'tag' => { 'stringCase' => 'upper' }
        }
      },
      :vocabularies => { STRING_CASE_VOCABULARY => { 'stringCase' => StringCase } },
      :ref_resolver => {
        URI('https://example.com/schemas/shouted-name') => {
          '$schema' => 'https://example.com/meta/string-case',
          'stringCase' => 'upper'
        },
        URI('https://example.com/meta/string-case') => meta_schema.merge(
          '$id' => 'https://example.com/meta/string-case'
        )
      }.to_proc
    )

    assert(schemer.valid?({ 'name' => 'ABC', 'tag' => 'not-uppercase' }))
    refute(schemer.valid?({ 'name' => 'abc' }))

    output = schemer.validate(
      { 'name' => 'ABC' },
      :output_format => 'basic',
      :resolve_enumerators => true
    )
    annotations = output.fetch('annotations')
    remote_annotation = annotations.find do |unit|
      unit.fetch('absoluteKeywordLocation') == 'https://example.com/schemas/shouted-name#/stringCase'
    end
    assert(remote_annotation)
    assert_equal('upper', remote_annotation.fetch('annotation'))
  end
end
