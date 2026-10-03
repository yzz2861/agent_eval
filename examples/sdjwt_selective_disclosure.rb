# frozen_string_literal: true

# Offline end-to-end example of selective disclosure with ruby-jwt.
#
#   ruby -Ilib examples/sdjwt_selective_disclosure.rb
#
# Three steps:
#   1. Issuer signs a credential, hiding selected claims behind salted digests.
#   2. Holder presents the token with only a subset of the disclosures.
#   3. Verifier checks the signature and reconstructs the provable claims.

require 'jwt'

key = 'shared-secret'

# --- Step 1: issuance -------------------------------------------------------
credential = {
  'sub'     => 'user-42',
  'email'   => 'alice@example.com',
  'address' => { 'street' => 'Main St 1', 'city' => 'Berlin' },
  'roles'   => %w[admin editor]
}

issued = JWT::SDJWT.issue(
  credential,
  key,
  algorithm: 'HS256',
  disclose: [
    [:email],            # object property
    [:address, :street], # nested object property
    [:roles, 1]          # array element
  ]
  # random: ->(n) { MyHSM.random_bytes(n) } # injectable secure random source
)

puts '1) Issued token (digests visible, claims hidden):'
decoded, = JWT.decode(issued.token, key, true, algorithm: 'HS256')
puts "   #{decoded.inspect}"
puts "   disclosures issued: #{issued.disclosures.length}"

# --- Step 2: holder presents a partial disclosure ---------------------------
# The holder reveals only the email and one role; the street stays hidden.
email = issued.disclosures.find { |d| d.name == 'email' }
role  = issued.disclosures.find { |d| d.array_element? }
presentation = issued.presentation([email, role])

puts '2) Presentation sent to the verifier:'
puts "   #{presentation}"

# --- Step 3: verification ---------------------------------------------------
claims = JWT::SDJWT.verify(presentation, key, algorithm: 'HS256')

puts '3) Reconstructed, provable claims:'
puts "   #{claims.inspect}"
puts '   note: address.street is absent (never disclosed) and cannot be forged'
