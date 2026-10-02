# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

module Rack

  module Session

    # Rack::Session::Revocation provides an optional, per-subject revocation
    # mechanism for session stores that keep all of their state on the client
    # (such as Rack::Session::Cookie). Because there is no server-side record
    # to delete, "logging out everywhere" (for example after a password
    # change) cannot be implemented by removing a row. Instead, each issued
    # session records the *generation* of its subject at issuance time, and
    # the server can atomically bump a subject's generation to invalidate
    # every session issued before that point.
    #
    # This is deliberately scoped to a single subject: revoking a subject
    # never affects any other subject, unlike rotating the global cookie
    # secrets which would sign out every user at once.
    #
    # A generation is a monotonically increasing Integer per subject.
    # Generation 0 is the implicit generation of any subject that has never
    # been revoked.
    module Revocation
      # Error raised by store implementations when the backing storage fails.
      # The middleware treats any StandardError from the store as a storage
      # failure, but raising this class is recommended for clarity.
      class Error < StandardError
      end

      # The storage interface a revocation store must implement. This class
      # documents the contract; stores do not need to inherit from it.
      #
      # Implementations must be safe for concurrent use: #revoke! must be
      # atomic with respect to itself and to #current_generation, so that a
      # concurrent revocation and issuance can never produce a session that
      # records a generation which was already invalidated.
      class Store
        # Returns the current generation of the given subject. Subjects that
        # have never been revoked must return 0.
        def current_generation(subject)
          raise NotImplementedError
        end

        # Atomically increments the subject's generation and returns the new
        # value. After this method returns, any session recording a lower
        # generation for this subject must be considered invalid.
        def revoke!(subject)
          raise NotImplementedError
        end
      end

      # A thread-safe, in-memory revocation store. Suitable for single-process
      # deployments and tests. Multi-process deployments should provide their
      # own implementation backed by shared storage (e.g. Redis or a
      # database), keeping the same atomicity guarantees.
      class Memory < Store
        def initialize
          @generations = Hash.new(0)
          @mutex = Mutex.new
        end

        def current_generation(subject)
          @mutex.synchronize do
            @generations[subject]
          end
        end

        def revoke!(subject)
          @mutex.synchronize do
            @generations[subject] += 1
          end
        end
      end
    end
  end
end
