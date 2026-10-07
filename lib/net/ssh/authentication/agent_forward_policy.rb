require 'net/ssh/buffer'

module Net
  module SSH
    module Authentication
      # A policy for one forwarded SSH agent connection. The policy is used by
      # AgentForwarder and does not alter the upstream agent or environment.
      class AgentForwardPolicy
        IdentityRequest = Struct.new(:blob, :comment, keyword_init: true)
        SignatureRequest = Struct.new(:blob, :data, :flags, :session,
                                      keyword_init: true)
        SessionBindRequest = Struct.new(:session_id, :is_forwarding,
                                        :upstream_host_key, :downstream_host_key,
                                        :session, keyword_init: true)
        ExtensionRequest = Struct.new(:name, :contents, :session_bind, :session,
                                      keyword_init: true)
        Decision = Struct.new(:allowed, :reason, keyword_init: true)

        SESSION_BIND_EXTENSION = "session-bind@openssh.com".freeze

        # Creates a policy. Each matcher may be +true+, a callable, an
        # enumerable, or a single value. Signature data may also be matched by
        # a Regexp or one of the built-in usage symbols.
        def initialize(identities: false, signatures: false, extensions: false,
                       session_bind: nil, session: nil)
          @identities = identities
          @signatures = signatures
          @extensions = extensions
          @session_bind = session_bind.nil? ? method(:allow_default_session_bind?) : session_bind
          @session = session
        end

        def allow_identity?(identity)
          allowed?(@identities, identity)
        end

        def allow_signature?(request)
          allowed?(@signatures, request.tap { |item| item.session = @session })
        end

        def self.userauth_request?(data)
          new.userauth?(data)
        end

        def allow_extension?(request)
          request.session = @session
          request.session_bind.session = @session if request.session_bind
          if request.session_bind
            allowed?(@session_bind, request)
          else
            allowed?(@extensions, request)
          end
        end

        def userauth?(data)
          buffer = Buffer.new(data.to_s)
          session_id = buffer.read_string
          return false unless session_id
          return false unless buffer.read_byte == 50
          user = buffer.read_string
          service = buffer.read_string
          method = buffer.read_string
          return false unless user && service == "ssh-connection" && method == "publickey"
          return false unless buffer.read_bool
          algorithm = buffer.read_string
          blob = buffer.read_string
          signature = buffer.read_string
          !!algorithm && !!blob && user && service == "ssh-connection" &&
            method == "publickey" && !!signature && buffer.eof?
        end

        private

        def allowed?(matcher, value)
          result = case matcher
                   when true then true
                   when false, nil then false
                   when Proc, Method then matcher.call(value)
                   when Hash then hash_match?(matcher, value)
                   when Regexp then matcher.match?(matcher_text(value))
                   when Enumerable then value_in?(matcher, value)
                   when Symbol then match_symbol?(matcher, value)
                   else scalar_match?(matcher, value)
                   end
          result ? Decision.new(allowed: true) : Decision.new(allowed: false, reason: "denied by agent forwarding policy")
        rescue => error
          Decision.new(false, "agent forwarding policy error: #{error.message}")
        end

        def matcher_text(value)
          value.respond_to?(:data) ? value.data.to_s : value.to_s
        end

        def value_in?(matcher, value)
          matcher.any? do |item|
            item.is_a?(Regexp) ? item.match?(matcher_text(value)) : scalar_match?(item, value)
          end
        end

        def hash_match?(matcher, value)
          return false unless value.is_a?(SignatureRequest)

          matcher.any? do |key, usage|
            key_match?(key, value.blob) && usage_match?(usage, value)
          end
        end

        def usage_match?(matcher, value)
        case matcher
          when true then true
          when false, nil then false
          when Proc, Method then matcher.call(value)
          when Regexp then matcher.match?(value.data.to_s)
          when Array then matcher.any? { |item| usage_match?(item, value) }
          when :userauth then userauth?(value.data)
          else matcher == value
          end
        end

        def match_symbol?(matcher, value)
          return userauth?(value.data) if matcher == :userauth && value.respond_to?(:data)

          scalar_match?(matcher, value)
        end

        def scalar_match?(matcher, value)
          case value
          when IdentityRequest
            key_match?(matcher, value.blob) || matcher == value.comment
          when SignatureRequest
            key_match?(matcher, value.blob)
          when SessionBindRequest
            matcher == value.session_id
          when ExtensionRequest
            matcher == value.name
          else
            matcher == value
          end
        end

        def key_match?(matcher, blob)
          matcher == blob || (matcher.respond_to?(:to_blob) && matcher.to_blob == blob)
        end

        def allow_default_session_bind?(request)
          binding = request.name == SESSION_BIND_EXTENSION && request.session_bind
          binding && request.session_bind.session_id.bytesize <= 256 &&
            [true, false].include?(request.session_bind.is_forwarding)
        end
      end
    end
  end
end
