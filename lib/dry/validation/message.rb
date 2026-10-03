# frozen_string_literal: true

module Dry
  module Validation
    # Message message
    #
    # @api public
    class Message < Schema::Message
      include ::Dry::Equalizer(:text, :path, :meta, :severity)

      # The error message text
      #
      # @return [String] text
      #
      # @api public
      attr_reader :text

      # The path to the value with the error
      #
      # @return [Array<Symbol, Integer>]
      #
      # @api public
      attr_reader :path

      # Optional hash with meta-data
      #
      # @return [Hash]
      #
      # @api public
      attr_reader :meta

      # The severity of the message (:error or :warning)
      #
      # @return [Symbol]
      #
      # @api public
      attr_reader :severity

      # A localized message type
      #
      # Localized messsages can be translated to other languages at run-time
      #
      # @api public
      class Localized < Message
        # Evaluate message text using provided locale
        #
        # @example
        #   result.errors[:email].evaluate(locale: :en, full: true)
        #   # "email is invalid"
        #
        # @param [Hash] opts
        # @option opts [Symbol] :locale Which locale to use
        # @option opts [Boolean] :full Whether message text should include the key name
        #
        # @api public
        def evaluate(**opts)
          evaluated_text, rest = text.(**opts)
          Message.new(evaluated_text, path: path, meta: rest.merge(meta), severity: severity)
        end
      end

      # Build a message
      #
      # @return [Message, Message::Localized]
      #
      # @api private
      def self.[](text, path, meta, severity = :error)
        klass = text.respond_to?(:call) ? Localized : Message
        klass.new(text, path: path, meta: meta, severity: severity)
      end

      # Initialize a new message object
      #
      # @api private
      # rubocop: disable Lint/MissingSuper
      def initialize(text, path:, meta: EMPTY_HASH, severity: :error)
        @text = text
        @path = Array(path)
        @meta = meta
        @severity = severity
      end
      # rubocop: enable Lint/MissingSuper

      # Check if this is a base message not associated with any key
      #
      # @return [Boolean]
      #
      # @api public
      def base?
        @base ||= path.compact.empty?
      end

      # Check if this is a warning
      #
      # Warnings don't affect the result's success status
      #
      # @return [Boolean]
      #
      # @api public
      def warning?
        severity.equal?(:warning)
      end

      # Dump message to a string
      #
      # @return [String]
      #
      # @api public
      def to_s
        text
      end
    end
  end
end
