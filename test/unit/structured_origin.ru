# frozen_string_literal: true

require 'rack/cors'

# A read-only API open to every site, but only the two admin consoles are
# trusted with credentials (cookies) and get a longer preflight cache time.
TRUSTED_ADMIN_SITES = %w[
  https://admin.example.com
  https://admin-backup.example.com
].freeze

use Rack::Cors do
  allow do
    # '*' is listed first, but specificity still decides the match:
    # exact block result > wildcard.
    origins '*' do |source, _env|
      if TRUSTED_ADMIN_SITES.include?(source)
        { credentials: true, max_age: 3600 }
      end
    end

    resource '/readonly/items', headers: :any, methods: %i[get options], max_age: 600
  end
end
