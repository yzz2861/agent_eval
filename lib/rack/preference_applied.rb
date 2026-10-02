# frozen_string_literal: true

require_relative 'constants'
require_relative 'preferences'

module Rack
  # Rack::PreferenceApplied implements the server side of the HTTP
  # +Prefer+ header framework (RFC 7240).
  #
  # The parsed request preferences are made available to the
  # application through the +rack.preferences+ environment key (a
  # Rack::Preferences instance, also accessible via
  # Rack::Request#preferences). The application explicitly declares
  # which of the requested preferences it honors:
  #
  #   preferences = env['rack.preferences']
  #   if preferences['return'] == 'minimal'
  #     preferences.apply('return')
  #   end
  #
  # After the application responds, the middleware generates the
  # +Preference-Applied+ response header from the declared preferences.
  # The client header is never echoed back verbatim: only preferences
  # the application actually applied are emitted, in normalized form.
  #
  # When +return=minimal+ is applied, the response body is discarded
  # (closing the original body if it responds to +close+) and entity
  # headers that no longer apply are removed, while the status and
  # non-entity metadata such as +location+ are preserved.
  class PreferenceApplied
    # Entity (representation) header fields removed when
    # +return=minimal+ is applied, since the response no longer
    # carries a representation.
    ENTITY_HEADERS = %w[
      content-encoding
      content-language
      content-length
      content-location
      content-md5
      content-range
      content-type
      etag
      last-modified
    ].freeze

    def initialize(app)
      @app = app
    end

    def call(env)
      preferences = env[RACK_PREFERENCES] ||= Preferences.parse(env['HTTP_PREFER'])
      status, headers, body = response = @app.call(env)

      applied = preferences.applied
      return response if applied.empty?

      if headers.frozen?
        headers = headers.dup
        response[1] = headers
      end

      merge_preference_applied(headers, preferences.applied_header)

      if preferences.applied?('return') &&
         preferences['return'].is_a?(String) &&
         preferences['return'].casecmp('minimal').zero?
        ENTITY_HEADERS.each { |field| headers.delete(field) }
        body.close if body.respond_to?(:close)
        response[2] = []
      end

      response
    end

    private

    # Combine a +Preference-Applied+ header set directly by the
    # application with the middleware-generated value. Existing
    # entries win on name conflicts and are never duplicated.
    def merge_preference_applied(headers, generated)
      if existing = headers[PREFERENCE_APPLIED]
        names = existing.to_s.split(',').map { |part| part.split('=', 2).first.strip.downcase }
        extra = generated.split(', ').reject do |part|
          names.include?(part.split('=', 2).first.strip.downcase)
        end
        headers[PREFERENCE_APPLIED] = (extra.unshift(existing.to_s)).join(', ') unless extra.empty?
      else
        headers[PREFERENCE_APPLIED] = generated
      end
    end
  end
end
