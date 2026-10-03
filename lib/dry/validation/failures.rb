# frozen_string_literal: true

require "dry/schema/path"
require "dry/validation/constants"

module Dry
  module Validation
    # Failure accumulator object
    #
    # @api public
    class Failures
      # The path for messages accumulated by failures object
      #
      # @return [Dry::Schema::Path]
      #
      # @api private
      attr_reader :path

      # Options for messages
      #
      # These options are used by MessageResolver
      #
      # @return [Hash]
      #
      # @api private
      attr_reader :opts

      # Options for warning messages
      #
      # These options are used by MessageResolver
      #
      # @return [Hash]
      #
      # @api private
      attr_reader :warning_opts

      # @api private
      def initialize(path = ROOT_PATH)
        @path = ::Dry::Schema::Path[path]
        @opts = EMPTY_ARRAY.dup
        @warning_opts = EMPTY_ARRAY.dup
      end

      # Set failure
      #
      # @overload failure(message)
      #   Set message text explicitly
      #   @param message [String] The message text
      #   @example
      #     failure('this failed')
      #
      # @overload failure(id)
      #   Use message identifier (needs localized messages setup)
      #   @param id [Symbol] The message id
      #   @example
      #     failure(:taken)
      #
      # @overload failure(meta_hash)
      #   Use meta_hash[:text] as a message (either explicitely or as an identifier),
      #   setting the rest of the hash as error meta attribute
      #   @param meta [Hash] The hash containing the message as value for the :text key
      #   @example
      #     failure({text: :invalid, key: value})
      #
      # @see Evaluator#key
      # @see Evaluator#base
      #
      # @api public
      def failure(message, tokens = EMPTY_HASH)
        opts << {message: message, tokens: tokens, path: path}
        self
      end

      # Set warning
      #
      # Warnings use the same message API as failures but they don't make
      # the result a failure. They are exposed separately via Result#warnings
      #
      # @overload warning(message)
      #   Set message text explicitly
      #   @param message [String] The message text
      #   @example
      #     warning('this could be better')
      #
      # @overload warning(id)
      #   Use message identifier (needs localized messages setup)
      #   @param id [Symbol] The message id
      #   @example
      #     warning(:weak_password)
      #
      # @overload warning(meta_hash)
      #   Use meta_hash[:text] as a message (either explicitely or as an identifier),
      #   setting the rest of the hash as warning meta attribute
      #   @param meta [Hash] The hash containing the message as value for the :text key
      #   @example
      #     warning({text: :weak_password, key: value})
      #
      # @see Failures#failure
      #
      # @api public
      def warning(message, tokens = EMPTY_HASH)
        warning_opts << {message: message, tokens: tokens, path: path}
        self
      end

      # @api private
      def empty?
        opts.empty?
      end
    end
  end
end
