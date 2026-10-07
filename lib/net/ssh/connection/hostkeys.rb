require 'net/ssh/buffer'
require 'net/ssh/loggable'

module Net
  module SSH
    module Connection
      # Implements the OpenSSH host-key rotation extension:
      #
      # * hostkeys-00@openssh.com — a global request the server sends after
      #   authentication, announcing the full public host keys it holds.
      # * hostkeys-prove-00@openssh.com — the client replies with the subset
      #   of announced keys it does not yet trust, and the server proves
      #   possession of the matching private keys with signatures bound to
      #   this session's session id, per draft-ietf-secsh-host-key-update /
      #   OpenSSH PROTOCOL:
      #
      #     string   HOSTKEYS_PROVE_MAGIC
      #     string   session id
      #     string   message number ("1")
      #     string   key (public key blob being proven)
      #
      #   The whole string is signed by the key itself.
      #
      # Only after every requested proof verifies are the new keys committed
      # to the known-hosts files. Update policy is explicit via the
      # :update_host_keys option (:add keeps existing keys, :replace removes
      # the keys presented in the announcement for the current logical host
      # and port before writing the new ones).
      class Hostkeys
        include Loggable

        ANNOUNCE = "hostkeys-00@openssh.com"
        PROVE_REQUEST = "hostkeys-prove-00@openssh.com"
        PROVE_MAGIC = "hostkeys-prove-00@openssh.com"

        # Policies accepted by the :update_host_keys option.
        POLICIES = [nil, false, :add, :replace].freeze

        attr_reader :session

        def initialize(session)
          @session = session
          self.logger = session.logger
          @policy = session.options[:update_host_keys]

          unless POLICIES.include?(@policy)
            raise ArgumentError,
                  "invalid :update_host_keys policy #{@policy.inspect} (expected :add or :replace)"
          end

          session.on_global_request(ANNOUNCE) { |data| announce(data) }
        end

        def enabled?
          @policy == :add || @policy == :replace
        end

        # Handles an incoming hostkeys-00@openssh.com announcement. Returns
        # :sent because the announcement wants no reply; the prove request
        # (if any) is the reply.
        def announce(data)
          return :sent unless enabled?

          keys = parse_announced_keys(data)
          return :sent if keys.empty?

          known_keys = transport.host_keys.to_a
          new_keys = keys.reject do |key|
            known_keys.any? { |known| known.respond_to?(:matches_key?) ? known.matches_key?(key) : same_key?(known, key) }
          end

          if new_keys.any?
            request_proofs(keys, new_keys)
          else
            debug { "server host keys already known; no update required" }
          end

          :sent
        end

        # Verifies the hostkeys-prove reply. The reply contains one signature
        # string per requested key, in request order. Returns the verified new
        # keys, or raises HostKeyProofFailed if any signature is missing or
        # invalid (in which case the known-hosts files are never touched).
        def verify_proofs(new_keys, reply_buffer)
          new_keys.each do |key|
            signature = begin
              reply_buffer.read_string
            rescue EOFError
              nil
            end

            unless signature && valid_proof?(key, signature)
              error { "hostkey proof for #{key.ssh_type} failed verification" }
              raise Net::SSH::HostKeyProofFailed,
                    "server failed to prove possession of announced host key #{key.ssh_type}"
            end
          end
        end

        # Commits verified keys to the known-hosts files according to the
        # configured policy. With :replace the announced keys (both the keys
        # already trusted and the newly proven ones) are removed first, so the
        # records converge on exactly what the server currently holds.
        def update_known_hosts(announced_keys, new_keys)
          host = options[:host_key_alias] || transport.host_as_string
          known_hosts = options.fetch(:known_hosts, KnownHosts)

          remove_keys = @policy == :replace ? announced_keys : []

          known_hosts.replace(host, new_keys, remove_keys, options)
        rescue SystemCallError => e
          error { "could not update known_hosts for #{host}: #{e.message}" }
          raise
        end

        private

        def transport
          session.transport
        end

        def options
          session.options
        end

        def parse_announced_keys(data)
          keys = []
          until data.eof?
            blob = data.read_string
            key = Net::SSH::Buffer.new(blob).read_key
            keys << key
          end
          keys
        rescue StandardError => e
          error { "ignoring malformed hostkeys announcement: #{e.message}" }
          []
        end

        def request_proofs(announced_keys, new_keys)
          debug { "requesting proof of #{new_keys.size} new host key(s)" }

          session.send_global_request(PROVE_REQUEST, *key_blobs(new_keys)) do |success, packet|
            next unless success

            verify_proofs(new_keys, packet)
            update_known_hosts(announced_keys, new_keys)
            info { "known_hosts updated with #{new_keys.size} new host key(s)" }
          end
        end

        def key_blobs(keys)
          keys.flat_map { |key| [:string, key.to_blob] }
        end

        def valid_proof?(key, signature_blob)
          buffer = Net::SSH::Buffer.new(signature_blob)
          sig_format = buffer.read_string
          signature = buffer.read_string
          signed_data = proof_data(key)

          key.ssh_do_verify(signature, signed_data, host_key: sig_format)
        rescue StandardError
          false
        end

        def proof_data(key)
          Net::SSH::Buffer.from(
            :string, PROVE_MAGIC,
            :string, transport.algorithms.session_id,
            :string, "1",
            :string, key.to_blob
          ).to_s
        end

        def same_key?(key, other)
          key.ssh_type == other.ssh_type && key.to_blob == other.to_blob
        end
      end
    end
  end
end
