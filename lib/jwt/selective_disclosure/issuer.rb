# frozen_string_literal: true

require 'set'

module JWT
  module SelectiveDisclosure
    # Builds a signed selectively-disclosable token from a payload and a set of
    # paths that should be disclosable rather than visible in the JWT body.
    class Issuer
      # @param payload [Hash] the complete claims object known to the issuer.
      # @param key [Object] the signing key passed to {JWT.encode}.
      # @param algorithm [String] the JWS signing algorithm.
      # @param disclosable_paths [Array<Array>] object field paths and array
      #   element indices that are replaced by digests.
      # @param salt_source [#call] injectable source of random salts.
      # @param header_fields [Hash] additional JWT header fields.
      def initialize(payload, key, algorithm = 'HS256', disclosable_paths: [], salt_source: nil, header_fields: {})
        raise ::JWT::EncodeError, 'Selective disclosure payload must be a Hash' unless payload.is_a?(::Hash)

        @payload = payload
        @key = key
        @algorithm = algorithm
        @salt_source = salt_source || SecureRandomSalt.new
        @header_fields = header_fields
        @disclosures = []
        @matched_paths = ::Set.new
        @selected = normalise_paths(disclosable_paths)
        @selected_set = ::Set.new(@selected)
      end

      # @return [IssuedToken] the signed token together with all disclosures.
      def issue
        skeleton = transform(@payload, [])
        ensure_all_paths_matched!
        skeleton[Format::SD_ALG_CLAIM] = Digester::HASH_ALGORITHM

        headers = @header_fields.merge('typ' => Format::TYPE)
        jwt = JWT.encode(skeleton, @key, @algorithm, headers)

        IssuedToken.new(jwt: jwt, disclosures: @disclosures)
      end

      private

      def ensure_all_paths_matched!
        missing = @selected.reject { |path| @matched_paths.include?(path) }
        return if missing.empty?

        raise ::JWT::InvalidDisclosurePath,
              "Disclosure path(s) not found in payload: #{missing.map(&:inspect).join(', ')}"
      end

      def normalise_paths(paths)
        normalised = paths.map { |path| Array(path).map(&:freeze).freeze }
        ensure_valid_paths!(normalised)
        normalised
      end

      def ensure_valid_paths!(paths)
        seen = ::Set.new
        paths.each do |path|
          raise ::JWT::InvalidDisclosurePath, 'Disclosure path must not be empty' if path.empty?
          unless path.all? { |segment| segment.is_a?(::String) || segment.is_a?(::Integer) }
            raise ::JWT::InvalidDisclosurePath, 'Disclosure path segments must be strings or integers'
          end
          raise ::JWT::InvalidDisclosurePath, "Duplicate disclosure path #{path.inspect}" unless seen.add?(path)
        end

        paths.each do |path|
          (1...path.size).each do |length|
            prefix = path[0, length]
            next unless seen.include?(prefix)

            raise ::JWT::InvalidDisclosurePath, "Path #{path.inspect} overlaps selected path #{prefix.inspect}"
          end
        end
      end

      # Walks the visible structure. A node selected at +path+ is disclosed in
      # full, so its subtree never enters the signed payload. Remaining hashes
      # and arrays are validated for reserved-marker collisions and recursed.
      def transform(value, path)
        return disclose_value(value, path) if @selected_set.include?(path)

        case value
        when ::Hash
          transform_hash(value, path)
        when ::Array
          transform_array(value, path)
        else
          value
        end
      end

      def transform_hash(hash, path)
        hash.each_with_object({}) do |(key, child), result|
          unless key.is_a?(::String)
            raise ::JWT::EncodeError, 'Selective disclosure payload keys must be strings'
          end
          if reserved_in_signed_payload?(key, path)
            raise ::JWT::EncodeError, "Payload claim #{key.inspect} conflicts with a selective disclosure marker"
          end

          child_path = path + [key]
          if @selected_set.include?(child_path)
            disclosure = build_disclosure(value: child, key: key)
            append_property_digest!(result, disclosure)
            @matched_paths.add(child_path)
            @disclosures << disclosure
          else
            result[key] = transform(child, child_path)
          end
        end
      end

      def transform_array(array, path)
        array.each_with_index.map do |child, index|
          child_path = path + [index]
          if @selected_set.include?(child_path)
            marker_for(disclose_value(child, child_path))
          else
            ensure_no_marker!(child)
            transform(child, child_path)
          end
        end
      end

      def reserved_in_signed_payload?(key, path)
        key == Format::SD_CLAIM || (path.empty? && key == Format::SD_ALG_CLAIM)
      end

      def append_property_digest!(result, disclosure)
        digests = (result[Format::SD_CLAIM] ||= [])
        digest = disclosure.digest
        raise ::JWT::EncodeError, "Duplicate digest for #{disclosure.key.inspect}" if digests.include?(digest)

        digests << digest
        digests.sort!
      end

      def disclose_value(value, path)
        disclosure = build_disclosure(value: value)
        @matched_paths.add(path)
        @disclosures << disclosure
        disclosure.digest
      end

      def marker_for(digest)
        { Format::ARRAY_MARKER => digest }
      end

      def build_disclosure(value:, key: nil)
        Disclosure.create(salt: @salt_source.call, key: key, value: value)
      end

      def ensure_no_marker!(value)
        return unless Format.array_marker?(value)

        raise ::JWT::EncodeError, "Payload contains reserved array marker #{Format::ARRAY_MARKER.inspect}"
      end
    end

  end
end
