# frozen_string_literal: true

require 'rack/attack/base_proxy'

module Rack
  class Attack
    module StoreProxy
      class DalliProxy < BaseProxy
        def self.handle?(store)
          return false unless defined?(::Dalli)

          # Consider extracting to a separate Connection Pool proxy to reduce
          # code here and handle clients other than Dalli.
          if defined?(::ConnectionPool) && store.is_a?(::ConnectionPool)
            store.with { |conn| conn.is_a?(::Dalli::Client) }
          else
            store.is_a?(::Dalli::Client)
          end
        end

        def initialize(client)
          super(client)
          stub_with_if_missing
        end

        def read(key)
          rescuing do
            with do |client|
              client.get(key)
            end
          end
        end

        def write(key, value, options = {})
          rescuing do
            with do |client|
              client.set(key, value, options.fetch(:expires_in, 0), raw: true)
            end
          end
        end

        def increment(key, amount, options = {})
          rescuing do
            with do |client|
              client.incr(key, amount, options.fetch(:expires_in, 0), amount)
            end
          end
        end

        def delete(key)
          rescuing do
            with do |client|
              client.delete(key)
            end
          end
        end

        private

        def stub_with_if_missing
          unless __getobj__.respond_to?(:with)
            class << self
              def with
                yield __getobj__
              end
            end
          end
        end

        def rescuing
          yield
        rescue Dalli::DalliError => e
          connection_errors = [
            defined?(Dalli::RingError) ? Dalli::RingError : nil,
            defined?(Dalli::NetworkError) ? Dalli::NetworkError : nil,
            defined?(Dalli::ServerUnavailableError) ? Dalli::ServerUnavailableError : nil,
            defined?(Dalli::DownError) ? Dalli::DownError : nil
          ].compact
          raise unless connection_errors.include?(e.class)

          raise Rack::Attack::StoreError, "dalli store unavailable"
        end
      end
    end
  end
end
