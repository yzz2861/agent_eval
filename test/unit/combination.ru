# frozen_string_literal: true

require 'rack/cors'

use Rack::Cors, combine: :intersection do
  allow do
    origins 'https://trusted.example.com'
    resource '/api/*',
      headers: :any,
      methods: %i[get post put delete],
      expose: %w[x-a x-b],
      max_age: 600,
      credentials: true,
      vary: %w[Host]
  end

  allow do
    origins 'https://trusted.example.com'
    resource '/api/admin/*',
      headers: %w[x-admin x-token],
      methods: %i[get post],
      expose: ['x-admin'],
      max_age: 300,
      credentials: true,
      vary: %w[X-Tenant]
  end
end
