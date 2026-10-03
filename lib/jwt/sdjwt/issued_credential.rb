# frozen_string_literal: true

module JWT
  module SDJWT
    # The result of issuing a selectively disclosable token: the signed JWT
    # plus every disclosure the holder may later choose to reveal.
    class IssuedCredential
      attr_reader :token, :disclosures

      def initialize(token:, disclosures:)
        @token       = token
        @disclosures = disclosures
      end

      # Serializes a presentation for the verifier.
      #
      # @param selected [Array<Disclosure>] the disclosures to reveal.
      #   Defaults to all disclosures; pass a subset for partial disclosure.
      # @return [String] jwt~disclosure~disclosure...
      def presentation(selected = disclosures)
        ([token] + selected.map(&:encode)).join(SEPARATOR)
      end
    end
  end
end
