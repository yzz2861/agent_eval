# frozen_string_literal: true

module Rack
  module Session
    module Revocation
      class StorageError < StandardError; end

      # Small interface required for per-subject session generation storage.
      class Store
        # Returns the current generation for a subject. Missing subjects must
        # return zero.
        def generation(subject)
          raise NotImplementedError, '#generation must return the current generation for a subject'
        end

        # Atomically increments and returns the new generation for a subject.
        def bump_generation!(subject)
          raise NotImplementedError, '#bump_generation! must atomically return the next generation'
        end
      end

      class MemoryStore < Store
        def initialize
          @generations = {}
          @mutex = Mutex.new
        end

        def generation(subject)
          @mutex.synchronize { @generations.fetch(subject, 0) }
        end

        def bump_generation!(subject)
          @mutex.synchronize do
            @generations[subject] = @generations.fetch(subject, 0) + 1
          end
        end

        alias revoke! bump_generation!
      end
    end
  end
end
