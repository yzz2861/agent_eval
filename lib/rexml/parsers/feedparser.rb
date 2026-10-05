# frozen_string_literal: false
require_relative "baseparser"
require_relative "../source"
require_relative "streamparser"

module REXML
  module Parsers
    # = Feed Parser
    # An event (SAX style) parser for input that arrives incrementally.
    #
    # Unlike StreamParser, which reads from a String or IO and blocks
    # until the whole document is available, FeedParser never reads
    # input itself.  Bytes are pushed in with #feed as they arrive
    # (from an event loop reading a socket, for example); events that
    # are completely determined by the data received so far are sent to
    # the listener immediately, and control returns when more input is
    # required.
    #
    #   parser = REXML::Parsers::FeedParser.new(listener)
    #   parser.feed(chunk) until parser.finished?
    #   parser.finish
    #
    # A tag, an attribute quote, an entity reference or a multi byte
    # character may span multiple chunks.  Running out of data in the
    # middle of such a construct is never reported as malformed XML;
    # genuine syntax errors are raised as soon as they can be detected.
    # The order of events is identical to the one produced by
    # StreamParser.
    class FeedParser < StreamParser
      # Creates a new feed parser.  +listener+ is an object that responds
      # to the REXML::StreamListener methods.  +initial_data+ may contain
      # the beginning of the document when it is already available.
      def initialize(listener, initial_data=nil)
        @listener = listener
        @source = FeedSource.new(initial_data)
        @parser = BaseParser.new(@source)
        @entities = {}
        @finished = false
      end

      # Feeds the next chunk of input and dispatches every event that
      # can be completely parsed from the data received so far.
      #
      # Returns self.  Raises REXML::ParseException as soon as a
      # genuine syntax error is detected.
      def feed(data)
        raise IOError, "already finished" if @finished
        @source.feed(data)
        process_available
        self
      end

      # Declares that all input has been fed.  Remaining events
      # (including the end of the document) are dispatched and a
      # truncated document raises REXML::ParseException.
      #
      # Returns self.  After finish, #feed can no longer be called.
      def finish
        raise IOError, "already finished" if @finished
        @finished = true
        @source.finish
        process_available
        self
      end

      # Returns true after #finish has been called and the complete
      # document has been parsed.
      def finished?
        @finished && @parser.empty?
      end

      private
      def process_available
        while true
          return if !@finished && @parser.empty?
          # The previous event was committed; discard its bytes
          # before saving a checkpoint for the next speculative pull.
          @source.trim!
          checkpoint = @parser.checkpoint
          begin
            event = @parser.pull
          rescue FeedSource::NeedMoreData
            @parser.restore(checkpoint)
            return
          rescue ParseException => error
            if error.continued_exception.is_a?(FeedSource::NeedMoreData)
              raise if @finished
              @parser.restore(checkpoint)
              return
            end
            # Some incomplete constructs (a name split across chunks,
            # a single leading token, or a helper that wrapped
            # NeedMoreData) are reported as syntax errors.  Before the
            # input is finished such an error is only genuine when
            # there is unconsumed, non-space data after the failure
            # point; otherwise the next chunk may complete it, so undo
            # the speculative parse.
            raise if @finished
            raise unless @source.parsed_to_end?
            @parser.restore(checkpoint)
            return
          end
          return if event[0] == :end_document
          process(event)
        end
      end
    end
  end
end
