# frozen_string_literal: true

module JWT
  module SDJWT
    # Verifies the signature of a selectively disclosable token and
    # reconstructs the claims proven by the presented disclosures.
    # Claims without a matching disclosure stay hidden.
    class Verifier
      HIDDEN = Object.new.freeze

      # @param presentation [String] jwt~disclosure~disclosure...
      # @param key [String] the verification key.
      # @param decode_options [Hash] options forwarded to JWT.decode
      #   (e.g. algorithm:, verify_expiration:).
      def initialize(presentation, key, decode_options = {})
        @presentation  = presentation
        @key           = key
        @decode_options = decode_options
      end

      # @return [Hash] the reconstructed, provable claims.
      def verify
        payload, disclosures = parse_presentation
        validate_sd_alg!(payload)
        context = Context.new(disclosures)
        claims  = resolve_value(payload, context)
        context.assert_no_orphans!
        claims
      end

      private

      def parse_presentation
        segments = @presentation.to_s.split(SEPARATOR)
        token    = segments.shift
        payload, = JWT.decode(token, @key, true, @decode_options)
        disclosures = segments.reject(&:empty?).map { |encoded| Disclosure.parse(encoded) }
        [payload, disclosures]
      end

      def validate_sd_alg!(payload)
        alg = payload[SD_ALG_KEY]
        return if alg.nil? || alg == SD_ALG

        raise UnsupportedSdAlgError, "Unsupported _sd_alg: #{alg.inspect} (only #{SD_ALG} is supported)"
      end

      def resolve_value(value, context)
        case value
        when Hash  then resolve_object(value, context)
        when Array then resolve_array(value, context)
        else value
        end
      end

      def resolve_object(object, context)
        digests = object[SD_KEY] || []
        raise MalformedDisclosureError, '_sd must be an array of digests' unless digests.is_a?(Array)

        result = {}
        object.each do |key, value|
          next if [SD_KEY, SD_ALG_KEY].include?(key)

          result[key] = resolve_value(value, context)
        end
        digests.each do |digest|
          context.register_digest!(digest)
          disclosure = context.disclosure_for(digest)
          next unless disclosure # undisclosed: stays hidden

          raise MalformedDisclosureError, 'Array element disclosure used for an object property' if disclosure.array_element?
          raise ClaimCollisionError, "Disclosed claim #{disclosure.name.inspect} collides with a plaintext claim" if result.key?(disclosure.name)

          context.consume!(disclosure)
          result[disclosure.name] = resolve_value(disclosure.value, context)
        end
        result
      end

      def resolve_array(array, context)
        resolved = array.map do |element|
          if array_digest?(element)
            resolve_array_element(element[ARRAY_DIGEST_KEY], context)
          else
            resolve_value(element, context)
          end
        end
        resolved.reject { |element| HIDDEN.equal?(element) }
      end

      def resolve_array_element(digest, context)
        context.register_digest!(digest)
        disclosure = context.disclosure_for(digest)
        return HIDDEN unless disclosure # undisclosed: element is dropped

        raise MalformedDisclosureError, 'Object property disclosure used for an array element' unless disclosure.array_element?

        context.consume!(disclosure)
        resolve_value(disclosure.value, context)
      end

      def array_digest?(element)
        element.is_a?(Hash) && element.keys == [ARRAY_DIGEST_KEY]
      end

      # Tracks the disclosures and digests seen while resolving a presentation.
      class Context
        def initialize(disclosures)
          @by_digest = {}
          disclosures.each do |disclosure|
            digest = disclosure.digest
            raise DuplicateDigestError, 'The same disclosure was provided twice' if @by_digest.key?(digest)

            @by_digest[digest] = disclosure
          end
          @seen_digests = []
          @consumed     = []
        end

        def register_digest!(digest)
          raise DuplicateDigestError, "Digest #{digest.inspect} appears more than once in the token" if @seen_digests.include?(digest)

          @seen_digests << digest
        end

        def disclosure_for(digest)
          @by_digest[digest]
        end

        def consume!(disclosure)
          @consumed << disclosure
        end

        def assert_no_orphans!
          orphans = @by_digest.values - @consumed
          return if orphans.empty?

          raise OrphanDisclosureError, "#{orphans.length} disclosure(s) do not match any digest in the token"
        end
      end
    end
  end
end
