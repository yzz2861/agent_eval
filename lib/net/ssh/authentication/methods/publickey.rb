require 'net/ssh/buffer'
require 'net/ssh/errors'
require 'net/ssh/authentication/methods/abstract'

module Net
  module SSH
    module Authentication
      module Methods
        # Implements the "publickey" SSH authentication method.
        class Publickey < Abstract
          # The signature algorithms that may be used with a certificate
          # bearing an RSA key ("ssh-rsa-cert-v01@openssh.com"), mapped to the
          # algorithm used to produce the signature itself.
          RSA_CERT_SIGNATURE_ALGORITHMS = {
            "rsa-sha2-512-cert-v01@openssh.com" => "rsa-sha2-512",
            "rsa-sha2-256-cert-v01@openssh.com" => "rsa-sha2-256",
            "ssh-rsa-cert-v01@openssh.com" => nil
          }.freeze

          # The signature algorithms that may be used with a bare RSA key
          # ("ssh-rsa"); the same key can be used with each of them, so the
          # choice cannot be derived from the key (or host key) type alone.
          RSA_SIGNATURE_ALGORITHMS = RSA_CERT_SIGNATURE_ALGORITHMS.keys.map do |cert_alg|
            cert_alg.sub(/-cert-v01@openssh\.com\z/, "")
          end.freeze

          # Attempts to perform public-key authentication for the given
          # username, trying each identity known to the key manager. If any of
          # them succeed, returns +true+, otherwise returns +false+. This
          # requires the presence of a key manager.
          def authenticate(next_service, username, password = nil)
            return false unless key_manager

            key_manager.each_identity do |identity|
              return true if authenticate_with(identity, next_service, username)
            end

            return false
          end

          private

          # Builds a packet that contains the request formatted for sending
          # a public-key request to the server.
          def build_request(pub_key, username, next_service, alg, has_sig)
            blob = Net::SSH::Buffer.new
            blob.write_key pub_key

            userauth_request(username, next_service, "publickey", has_sig,
                             alg, blob.to_s)
          end

          # Builds and sends a request formatted for a public-key
          # authentication request.
          def send_request(pub_key, username, next_service, alg, signature = nil)
            msg = build_request(pub_key, username, next_service, alg,
                                !signature.nil?)
            msg.write_string(signature) if signature
            send_message(msg)
          end

          def authenticate_with_alg(identity, next_service, username, alg, sig_alg = nil)
            debug { "trying publickey (#{identity.fingerprint}) alg #{alg}" }
            send_request(identity, username, next_service, alg)

            message = session.next_message

            case message.type
            when USERAUTH_PK_OK
              buffer = build_request(identity, username, next_service, alg,
                                     true)
              sig_data = Net::SSH::Buffer.new
              sig_data.write_string(session_id)
              sig_data.append(buffer.to_s)

              sig_blob = key_manager.sign(identity, sig_data, sig_alg)

              send_request(identity, username, next_service, alg, sig_blob.to_s)
              message = session.next_message

              case message.type
              when USERAUTH_SUCCESS
                debug { "publickey succeeded (#{identity.fingerprint})" }
                return true
              when USERAUTH_FAILURE
                debug { "publickey failed (#{identity.fingerprint})" }

                raise Net::SSH::Authentication::DisallowedMethod unless
                  message[:authentications].split(/,/).include? 'publickey'

                return false
              else
                raise Net::SSH::Exception,
                      "unexpected server response to USERAUTH_REQUEST: #{message.type} (#{message.inspect})"
              end

            when USERAUTH_FAILURE
              return false
            when USERAUTH_SUCCESS
              return true

            else
              raise Net::SSH::Exception, "unexpected reply to USERAUTH_REQUEST: #{message.type} (#{message.inspect})"
            end
          end

          # Attempts to perform public-key authentication for the given
          # username, with the given identity (public key). Returns +true+ if
          # successful, or +false+ otherwise.
          def authenticate_with(identity, next_service, username)
            type = identity.ssh_type
            if type == "ssh-rsa"
              select_signature_algorithms(pubkey_algorithms & RSA_SIGNATURE_ALGORITHMS).each do |pk_alg|
                return true if authenticate_with_alg(identity, next_service, username, pk_alg, pk_alg)
              end
            elsif type == "ssh-rsa-cert-v01@openssh.com"
              select_signature_algorithms(pubkey_algorithms & RSA_CERT_SIGNATURE_ALGORITHMS.keys).each do |pk_alg|
                return true if authenticate_with_alg(identity, next_service, username, pk_alg, RSA_CERT_SIGNATURE_ALGORITHMS[pk_alg])
              end
            elsif authenticate_with_alg(identity, next_service, username, type)
              # success
              return true
            end
            # failure
            return false
          end

          private

          # Narrows the candidate signature algorithms down to those the
          # server also accepts, as reported by the "server-sig-algs"
          # extension (RFC 8308). When the server did not send that extension,
          # the candidates are returned unchanged, preserving the legacy
          # trial-and-error behavior. When the extension was received but
          # names none of the candidates, Net::SSH::Exception is raised
          # explaining the mismatch.
          def select_signature_algorithms(candidates)
            return candidates if server_sig_algs.nil?

            selected = candidates.select { |algorithm| server_sig_algs.include?(algorithm) }
            if selected.empty?
              raise Net::SSH::Exception,
                    "could not settle on publickey signature algorithm\n" \
                    "Server signature algorithms: #{server_sig_algs.join(',')}\n" \
                    "Client signature algorithms: #{candidates.join(',')}"
            end

            debug { "server-sig-algs restricts signature algorithms to: #{selected.join(', ')}" }
            selected
          end
        end
      end
    end
  end
end
