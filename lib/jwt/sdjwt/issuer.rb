# frozen_string_literal: true

require 'securerandom'

module JWT
  module SDJWT
    # Replaces the selected claim values with salted digests and signs the
    # resulting payload as a regular JWT.
    class Issuer
      SALT_BYTES = 16

      # @param payload [Hash] the claims to issue.
      # @param key [String] the signing key.
      # @param algorithm [String] the JWT signing algorithm.
      # @param disclose [Array<Array>] claim paths to make selectively
      #   disclosable, e.g. [[:email], [:address, :street], [:tags, 0]].
      #   Hash keys may be strings or symbols, array elements are addressed
      #   by integer index.
      # @param random [#call] injectable secure random source, called with a
      #   byte count and expected to return that many random bytes.
      # @param headers [Hash] additional JWT headers.
      def initialize(payload, key, algorithm:, disclose: [], random: nil, headers: {})
        @payload   = JSON.parse(JSON.generate(payload))
        @key       = key
        @algorithm = algorithm
        @headers   = headers
        @paths     = disclose.map { |path| normalize_path(path) }
        @random    = random || SecureRandom.method(:random_bytes)
        validate_paths!
      end

      # @return [IssuedCredential] the signed token and all disclosures.
      def issue
        disclosures = []
        sd_payload  = JSON.parse(JSON.generate(@payload))
        # Deepest paths first so that an outer disclosure captures the
        # already-transformed (digest-containing) inner value.
        @paths.sort_by { |path| -path.length }.each do |path|
          disclosures << apply_path(sd_payload, path)
        end
        sd_payload[SD_ALG_KEY] = SD_ALG unless disclosures.empty?
        token = JWT.encode(sd_payload, @key, @algorithm, @headers)
        IssuedCredential.new(token: token, disclosures: disclosures)
      end

      private

      def normalize_path(path)
        path = [path] unless path.is_a?(Array)
        raise IssuanceError, 'Disclosure path must not be empty' if path.empty?

        path.map { |segment| segment.is_a?(Integer) ? segment : segment.to_s }
      end

      def validate_paths!
        return unless @paths.uniq.length != @paths.length

        raise IssuanceError, 'Duplicate disclosure paths'
      end

      def apply_path(root, path)
        parent = path[0..-2].reduce(root) { |node, key| fetch_node(node, key, path) }
        key    = path[-1]
        if parent.is_a?(Array)
          hide_array_element(parent, key, path)
        elsif parent.is_a?(Hash)
          hide_object_property(parent, key, path)
        else
          raise IssuanceError, "Cannot disclose #{path.inspect}: parent is not a container"
        end
      end

      def fetch_node(node, key, path)
        value = if node.is_a?(Array)
                  key.is_a?(Integer) ? node[key] : nil
                elsif node.is_a?(Hash)
                  node[key]
                end
        raise IssuanceError, "Cannot disclose #{path.inspect}: path does not exist" if value.nil?

        value
      end

      def hide_array_element(parent, index, path)
        unless index.is_a?(Integer) && index >= 0 && index < parent.length
          raise IssuanceError, "Cannot disclose #{path.inspect}: invalid array index"
        end

        disclosure    = Disclosure.new(salt: new_salt, value: parent[index])
        parent[index] = { ARRAY_DIGEST_KEY => disclosure.digest }
        disclosure
      end

      def hide_object_property(parent, key, path)
        raise IssuanceError, "Cannot disclose #{path.inspect}: path does not exist" unless parent.key?(key)
        raise IssuanceError, "Cannot disclose #{path.inspect}: reserved claim" if [SD_KEY, SD_ALG_KEY].include?(key)

        disclosure = Disclosure.new(salt: new_salt, name: key, value: parent.delete(key))
        (parent[SD_KEY] ||= []) << disclosure.digest
        disclosure
      end

      def new_salt
        Base64.url_encode(@random.call(SALT_BYTES))
      end
    end
  end
end
