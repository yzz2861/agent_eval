require 'net/ssh/buffer'
require 'net/ssh/known_hosts'
require 'net/ssh/loggable'

module Net
  module SSH
    module Connection
      class HostKeyRotator
        include Loggable
        include Constants

        HOSTKEYS_REQUEST = "hostkeys-00@openssh.com"
        PROVE_REQUEST = "hostkeys-prove-00@openssh.com"
        SERVICE = "ssh-connection"

        def self.install(session, username, options = session.options, service: SERVICE)
          return false unless enabled?(options)

          new(session, username, service, options).install
          true
        end

        def self.enabled?(options)
          return false unless options.key?(:update_host_keys)

          !options[:update_host_keys].nil? &&
            options[:update_host_keys] != false &&
            !%i[no off].include?(options[:update_host_keys])
        end

        def initialize(session, username, service = SERVICE, options = session.options)
          @session = session
          @transport = session.transport
          @options = options
          @username = username
          @service = service
          self.logger = session.logger

          normalize_policy
        end

        def install
          @session.on_global_request(HOSTKEYS_REQUEST, &method(:announcement))
          self
        end

        private

        def normalize_policy
          case @options[:update_host_keys]
          when true, :yes, :on, :add
            @policy = -> { true }
          when :replace
            @policy = -> { :replace }
          when :ask
            @policy = method(:ask_policy)
          when Proc, Method
            @policy = @options[:update_host_keys]
          else
            raise ArgumentError,
                  "invalid :update_host_keys policy #{@options[:update_host_keys].inspect}"
          end
        end

        def announcement(packet, want_reply)
          return :sent if @state

          state = { want_reply: want_reply }
          announced_keys = read_keys(packet)
          current_key = @transport.server_host_key
          host = @options[:host_key_alias] || @transport.host_as_string
          source = KnownHosts.source_for_key(host, current_key, @options)

          return failure_reply(state) unless current_key && !certificate?(current_key) && source
          return failure_reply(state) if announced_keys.empty? ||
                                        announced_keys.any? { |key| certificate?(key) }

          new_keys = announced_keys.reject do |key|
            @transport.host_keys.any? { |known_key| known_key.to_blob == key.to_blob }
          end
          return success_reply(state) if new_keys.empty?

          @state = state.merge(
            host: host,
            source: source,
            announced_keys: announced_keys,
            new_keys: new_keys
          )

          request_proof(@state)
          :sent
        rescue StandardError => error
          debug { "host key announcement rejected: #{error.message}" }
          failure_reply(@state)
        end

        def request_proof(state)
          session_id = @transport.algorithms.session_id
          @session.send_global_request(
            PROVE_REQUEST,
            :string, session_id,
            :string, @username,
            :string, @service
          ) do |success, packet|
            proof_result(success, packet, state)
          end
        end

        def proof_result(success, packet, state)
          return failure_reply(state) unless success && verify_proofs(packet, state[:new_keys])

          apply_policy(state)
        rescue StandardError => error
          debug { "host key proof rejected: #{error.class}: #{error.message}" }
          failure_reply(state)
        end

        def verify_proofs(packet, keys)
          proofs = read_proofs(packet)
          session_id = @transport.algorithms.session_id
          signed_data = Buffer.from(
            :string, session_id,
            :string, @username,
            :string, @service,
            :string, PROVE_REQUEST
          ).to_s

          return false unless proofs.keys.sort == keys.map(&:to_blob).sort

          keys.all? do |key|
            signature_algorithm, signature_value = proofs.fetch(key.to_blob)

            valid_signature_algorithm?(key.ssh_type, signature_algorithm) &&
              key.ssh_do_verify(signature_value, signed_data,
                                host_key: signature_algorithm)
          end
        end

        def read_proofs(packet)
          proofs = {}
          until packet.eof?
            key = packet.read_key
            signature_algorithm = packet.read_string
            signature = packet.read_string
            return {} if key.nil? || signature_algorithm.nil? ||
                          signature.nil? || proofs.key?(key.to_blob)

            proofs[key.to_blob] = [signature_algorithm, signature]
          end
          proofs
        end

        def apply_policy(state)
          add_keys, remove_old_keys = decision_flags(call_policy(state))
          return success_reply(state) unless add_keys

          KnownHosts.new(state[:source]).update(
            state[:host], state[:announced_keys], @options,
            remove_old_keys: remove_old_keys,
            add_keys: state[:new_keys]
          )
          success_reply(state)
        rescue SystemCallError => error
          debug { "could not update known_hosts: #{error.message}" }
          failure_reply(state)
        end

        def call_policy(state)
          context = {
            host: state[:host],
            source: state[:source],
            current_key: @transport.server_host_key,
            announced_keys: state[:announced_keys],
            new_keys: state[:new_keys]
          }
          return call_policy_with_context(context) if accepts_policy_context?

          @policy.call
        end

        def accepts_policy_context?
          @policy.respond_to?(:parameters) &&
            (@policy.arity != 0 ||
             @policy.parameters.any? { |type, _name| type.to_s.start_with?("key") })
        end

        def call_policy_with_context(context)
          parameters = @policy.parameters.map(&:first)
          if parameters.any? { |type| type.to_s.start_with?("key") }
            @policy.call(**context)
          else
            @policy.call(context)
          end
        end

        def decision_flags(decision)
          case decision
          when true, :yes, :on, :add
            [true, false]
          when :replace
            [true, true]
          when false, nil, :no, :off
            [false, false]
          else
            raise ArgumentError, "invalid host key update decision #{decision.inspect}"
          end
        end

        def ask_policy
          prompter = (@options[:password_prompt] || Net::SSH::Prompt.default).start(type: "update_host_keys")
          response = prompter.ask("Accept updated hostkeys? (yes/no): ", true).to_s
          /\Ay(?:es)?\z/i.match?(response)
        ensure
          prompter&.success
        end

        def read_keys(buffer)
          keys = []
          until buffer.eof?
            key = buffer.read_key
            raise Net::SSH::Exception, "truncated host key announcement" if key.nil?
            raise Net::SSH::Exception, "duplicate host key announcement" if
              keys.any? { |existing| existing.to_blob == key.to_blob }

            keys << key
          end
          keys
        end

        def certificate?(key)
          key.ssh_type.end_with?("-cert-v01@openssh.com")
        end

        def valid_signature_algorithm?(key_algorithm, signature_algorithm)
          signature_algorithm == key_algorithm ||
            (key_algorithm == "ssh-rsa" &&
              %w[ssh-rsa rsa-sha2-256 rsa-sha2-512].include?(signature_algorithm))
        end

        def success_reply(state = nil)
          reply(true, state)
        end

        def failure_reply(state = nil)
          reply(false, state)
        end

        def reply(success, state)
          if state.nil? || state[:want_reply]
            @session.send_message(Buffer.from(:byte, success ? REQUEST_SUCCESS : REQUEST_FAILURE))
          end
          :sent
        end
      end
    end
  end
end
