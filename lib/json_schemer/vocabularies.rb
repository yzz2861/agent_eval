# frozen_string_literal: true
module JSONSchemer
  class Vocabularies
    CORE_KEYWORDS = [
      Draft202012::Vocab::CORE,
      Draft201909::Vocab::CORE
    ].flat_map(&:keys).uniq.freeze

    def self.normalize(vocabularies)
      return vocabularies if vocabularies.is_a?(self)
      new(vocabularies || {})
    end

    def initialize(vocabularies = {})
      @vocabularies = {}
      vocabularies.each do |uri, keywords|
        register(uri, keywords)
      end
    end

    def register(uri, keywords)
      uri = uri.to_s
      validate(uri, keywords)
      @vocabularies[uri] = stringify_keys(keywords)
      self
    end

    def [](uri)
      @vocabularies[uri.to_s] || built_in_vocabularies[uri.to_s]
    end

    def key?(uri)
      uri = uri.to_s
      @vocabularies.key?(uri) || built_in_vocabularies.key?(uri)
    end

    def fetch(uri, *args, &block)
      @vocabularies.fetch(uri.to_s) { built_in_vocabularies.fetch(uri.to_s, *args, &block) }
    end

    private

    def built_in_vocabularies
      @built_in_vocabularies ||= VOCABULARIES.dup.freeze
    end

    def validate(uri, keywords)
      raise InvalidVocabulary, "#{uri} is a built-in vocabulary" if built_in_vocabularies.key?(uri)

      unless keywords.is_a?(Hash)
        raise InvalidVocabulary, "vocabulary #{uri} keywords must be a Hash"
      end

      keywords.each do |keyword, keyword_class|
        keyword = keyword.to_s

        unless keyword_class.is_a?(Class) && keyword_class <= Keyword
          raise InvalidVocabulary, "vocabulary keyword #{uri}##{keyword} must be a JSONSchemer::Keyword subclass"
        end

        if CORE_KEYWORDS.include?(keyword)
          raise InvalidVocabulary, "vocabulary #{uri} must not override core keyword #{keyword}"
        end
      end
    end

    def stringify_keys(keywords)
      keywords.each_with_object({}) do |(keyword, keyword_class), out|
        out[keyword.is_a?(Symbol) ? keyword.name : keyword.to_s] = keyword_class
      end
    end
  end
end
