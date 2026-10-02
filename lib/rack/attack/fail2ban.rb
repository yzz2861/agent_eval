# frozen_string_literal: true

module Rack
  class Attack
    class Fail2Ban
      class << self
        def filter(discriminator, options)
          bantime   = options[:bantime]   or raise ArgumentError, "Must pass bantime option"
          findtime  = options[:findtime]  or raise ArgumentError, "Must pass findtime option"
          maxretry  = options[:maxretry]  or raise ArgumentError, "Must pass maxretry option"

          if banned?(discriminator) == true
            # Return true for blocklist
            true
          elsif yield
            fail!(discriminator, bantime, findtime, maxretry)
          end
        end

        def reset(discriminator, options)
          findtime = options[:findtime] or raise ArgumentError, "Must pass findtime option"
          cache.reset_count("#{key_prefix}:count:#{discriminator}", findtime)
          # Clear ban flag just in case it's there
          cache.delete("#{key_prefix}:ban:#{discriminator}")
        end

        def banned?(discriminator)
          value = cache.read("#{key_prefix}:ban:#{discriminator}")
          value ? true : false
        rescue Rack::Attack::StoreError
          nil
        end

        protected

        def key_prefix
          'fail2ban'
        end

        def fail!(discriminator, bantime, findtime, maxretry)
          with_store_error_rescue { fail_with_count(discriminator, bantime, findtime, maxretry) }
        end

        private

        def ban!(discriminator, bantime)
          with_store_error_rescue { cache.write("#{key_prefix}:ban:#{discriminator}", 1, bantime) }
        end

        def fail_with_count(discriminator, bantime, findtime, maxretry)
          count = cache.count("#{key_prefix}:count:#{discriminator}", findtime)
          if count >= maxretry
            ban!(discriminator, bantime)
          end

          true
        end

        def with_store_error_rescue
          yield
        rescue Rack::Attack::StoreError
          nil
        end

        def cache
          Rack::Attack.cache
        end
      end
    end
  end
end
