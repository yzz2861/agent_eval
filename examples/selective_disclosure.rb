#!/usr/bin/env ruby
# frozen_string_literal: true

# Offline end-to-end example: issue -> holder presents a subset -> verify.
# Run with: ruby examples/selective_disclosure.rb

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'jwt'

SD = JWT::SelectiveDisclosure

# An injectable salt source. In production omit it and the issuer uses
# SecureRandom (16 random bytes per disclosure).
salt_counter = [0]
deterministic_salt = -> { "salt-#{salt_counter[0] += 1}" }

secret = 'issuer-signing-secret'

# The issuer knows everything. Selected paths are replaced by salted SHA-256
# digests in the signed JWT; their values never appear in the token body.
full_claims = {
  'iss' => 'https://issuer.example',
  'given_name' => 'Ada',
  'family_name' => 'Lovelace',
  'address' => {
    'street_address' => '1 Calculator Row',
    'locality' => 'London',
    'country' => 'GB'
  },
  'nationalities' => ['GB', 'FR'],
  'over_18' => true
}

issued = SD.issue(
  full_claims,
  secret,
  'HS256',
  disclosable_paths: [
    ['given_name'],
    ['family_name'],
    ['address', 'street_address'],
    ['address', 'locality'],
    ['nationalities', 0],
    ['nationalities', 1]
  ],
  salt_source: deterministic_salt
)

puts '=== 1) Issued combined token (JWT signed; hidden fields are only digests) ==='
puts issued.to_s
puts
puts 'Signed payload (note the digests, no hidden values):'
signed_payload = JWT::JSON.parse(JWT::Base64.url_decode(issued.jwt.split('.')[1]))
puts JSON.pretty_generate(signed_payload)
puts

# 2) The holder picks what to reveal: given_name and the second nationality only.
given_name = issued.disclosures.find { |d| d.key == 'given_name' }
french = issued.disclosures.find { |d| d.array_element? && d.value == 'FR' }
presentation = issued.present(given_name, french)

puts '=== 2) Holder presentation (subset of disclosures) ==='
puts presentation
puts

# 3) The verifier checks the JWT signature, then matches the presented
# disclosures against the digests anchored in the signed payload.
result = SD.verify(presentation, secret, 'HS256')

puts '=== 3) Verified, provable claims ==='
puts JSON.pretty_generate(result.claims)
puts
puts "Revealed keys: #{result.disclosed_keys.inspect}"
puts 'family_name / street / GB nationality stay invisible to the verifier.'

# A combined token is not an ordinary JWT and must not be accepted as one.
begin
  JWT.decode(presentation, secret, true, algorithm: 'HS256')
rescue JWT::Error => e
  puts
  puts "Ordinary JWT.decode rejects the format: #{e.class}"
end
