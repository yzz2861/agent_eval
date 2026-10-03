# frozen_string_literal: true

require 'set'

module JWT
  module SelectiveDisclosure
    # @api private
    #
    # Rebuilds the provable claims from the signed skeleton and the presented
    # disclosures. Every accepted disclosure must match a digest anchored inside
    # the signed payload, so reconstructed claims are covered by the signature.
    class Resolver
      def initialize(payload, disclosures)
        @payload = payload
        @by_digest = {}
        disclosures.each do |disclosure|
          digest = disclosure.digest
          if @by_digest.key?(digest)
            raise ::JWT::DuplicateDigest, 'Same disclosure digest presented more than once'
          end

          @by_digest[digest] = disclosure
        end
        @consumed = ::Set.new
      end

      # @return [Hash] the reconstructed, provable claims.
      def resolve!
        count_anchored_digests!(@payload)
        resolved = resolve_hash(@payload, top_level: true)

        orphans = @by_digest.keys.reject { |digest| @consumed.include?(digest) }
        unless orphans.empty?
          raise ::JWT::OrphanDisclosure, "#{orphans.size} presented disclosure(s) match no digest in the signed payload"
        end

        resolved
      end

      private

      # First pass: verify marker shapes and reject a digest anchored more than
      # once even when the holder never presents the corresponding disclosure.
      def count_anchored_digests!(value)
        case value
        when ::Hash
          if value.key?(Format::SD_CLAIM)
            validate_property_digests!(value[Format::SD_CLAIM])
          end
          value.each do |key, child|
            next if key == Format::SD_CLAIM

            raise ::JWT::MalformedSDToken, 'Payload keys must be strings' unless key.is_a?(::String)

            count_anchored_digests!(child)
          end
        when ::Array
          value.each do |child|
            if Format.array_marker?(child)
              remember_anchor!(marker_digest(child))
            else
              reject_marker_shape!(child)
              count_anchored_digests!(child)
            end
          end
        when ::String, ::Numeric, ::TrueClass, ::FalseClass, ::NilClass
          nil
        else
          raise ::JWT::MalformedSDToken, "Unsupported payload value of type #{value.class}"
        end
      end

      def validate_property_digests!(digests)
        unless digests.is_a?(::Array) && digests.all?(::String)
          raise ::JWT::MalformedSDToken, "#{Format::SD_CLAIM.inspect} must be an array of digest strings"
        end

        digests.each { |digest| remember_anchor!(digest) }
      end

      # A single-key "..." hash is reserved as an array marker; it is invalid
      # anywhere else inside an array, regardless of the value it carries.
      def reject_marker_shape!(value)
        return unless value.is_a?(::Hash) && value.size == 1 && value.key?(Format::ARRAY_MARKER)

        raise ::JWT::MalformedSDToken, "Unexpected array marker #{Format::ARRAY_MARKER.inspect} outside an element slot"
      end

      def remember_anchor!(digest)
        @anchors ||= ::Set.new
        if @anchors.include?(digest)
          raise ::JWT::DuplicateDigest, 'Digest anchored more than once in the signed payload'
        end

        @anchors.add(digest)
      end

      def resolve_node(value)
        case value
        when ::Hash then resolve_hash(value)
        when ::Array then resolve_array(value)
        else value
        end
      end

      def resolve_hash(hash, top_level: false)
        result = {}

        hash.each do |key, child|
          next if key == Format::SD_CLAIM
          next if top_level && key == Format::SD_ALG_CLAIM

          result[key] = resolve_node(child)
        end

        Array(hash[Format::SD_CLAIM]).each do |digest|
          disclosure = @by_digest[digest]
          next unless disclosure
          unless disclosure.property?
            raise ::JWT::InvalidDisclosure, 'Array element disclosure matched an object digest'
          end

          key = disclosure.key
          if Format.reserved_claim?(key) || result.key?(key)
            raise ::JWT::DisclosureCollision, "Disclosed claim #{key.inspect} collides with a visible or reserved claim"
          end

          consume!(digest)
          result[key] = resolve_node(disclosure.value)
        end

        result
      end

      def resolve_array(array)
        array.each_with_object([]) do |child, result|
          if Format.array_marker?(child)
            digest = marker_digest(child)
            disclosure = @by_digest[digest]
            # An undisclosed array element is removed rather than left as a marker.
            next unless disclosure
            unless disclosure.array_element?
              raise ::JWT::InvalidDisclosure, 'Object disclosure matched an array element digest'
            end

            consume!(digest)
            result << resolve_node(disclosure.value)
          else
            result << resolve_node(child)
          end
        end
      end

      def marker_digest(marker)
        marker[Format::ARRAY_MARKER].tap do |digest|
          raise ::JWT::MalformedSDToken, 'Array element marker must carry a digest string' unless digest.is_a?(::String)
        end
      end

      def consume!(digest)
        @consumed.add(digest)
      end
    end
  end
end
