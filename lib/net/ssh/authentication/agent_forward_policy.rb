require 'net/ssh/buffer'

module Net
  module SSH
    module Authentication
      # Per-session policy used when an authentication agent is forwarded over
      # an SSH connection. The policy never changes the local agent's state.
      class AgentForwardPolicy
        SSH2_AGENT_REQUEST_IDENTITIES = 11
        SSH2_AGENT_IDENTITIES_ANSWER  = 12
        SSH2_AGENT_SIGN_REQUEST       = 13

        # Creates a policy. Identities may be an array of public keys/public key
        # blobs, the symbol +:all+, or a callable receiving an identity. Sign
        # uses may be a callable receiving the sign request or +:all+.
        def initialize(identities: nil, sign: nil)
          @identities = identities
          @sign = sign
        end

        # Returns true when a complete identity-listing request may be sent to
        # the local agent.
        def allow_identities_request?(_request)
          @identities == :all || @identities.is_a?(Array) || @identities.respond_to?(:call)
        end

        # Filters a parsed identity answer. +identities+ contains hashes with
        # +:blob+ and +:comment+.
        def filter_identities(identities)
          case @identities
          when :all
            identities
          when Proc, Method
            identities.select { |identity| @identities.call(identity) }
          else
            allowed = Array(@identities).map { |identity| key_blob(identity) }
            identities.select { |identity| allowed.include?(identity[:blob]) }
          end
        end

        # Returns true when a complete signature request may use the local
        # agent. The request hash contains +:key+, +:blob+, +:data+, and
        # +:flags+.
        def allow_sign?(request)
          return false unless identity_allowed?(request[:blob])

          case @sign
          when :all then true
          when ->(value) { value.respond_to?(:call) } then @sign.call(request)
          else false
          end
        end

        private

        def identity_allowed?(blob)
          case @identities
          when :all then true
          when Proc, Method
            begin
              key = Net::SSH::Buffer.new(blob).read_key
            rescue StandardError
              key = nil
            end
            key && @identities.call(key: key, blob: blob, comment: nil)
          else
            Array(@identities).map { |identity| key_blob(identity) }.include?(blob)
          end
        end

        def key_blob(identity)
          identity.respond_to?(:to_blob) ? identity.to_blob : identity.to_s
        end
      end
    end
  end
end
