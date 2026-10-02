# frozen_string_literal: true

require 'rack/cors'

# A read-only API open to every origin, where only two trusted admin
# sites may send credentials. The wildcard rule is deliberately declared
# first: the more specific trusted-site rules must still win for those
# origins, and the wildcard must never be combined with credentials.
use Rack::Lint
use Rack::Cors do
  allow do
    origins '*',
            { 'https://admin-one.example.com' => { credentials: true, max_age: 1200 } },
            { 'https://admin-two.example.com' => { credentials: true, max_age: 1200 } }

    resource '/api/data', methods: [:get], headers: :any
  end
end
