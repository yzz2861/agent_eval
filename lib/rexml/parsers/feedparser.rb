# frozen_string_literal: false
require_relative "baseparser"
require_relative "../feedsource"

module REXML
  module Parsers
    # = Using the Feed Parser
    #
    # A push-style streaming parser: the caller owns reading the input
    # (for example, a non-blocking socket in an event loop) and pushes
    # chunks of data into the parser instead of letting the parser
    # block on IO:
    #
    #   parser = REXML::Parsers::FeedParser.new(listener)
    #   parser.feed("<root>first chunk")
    #   parser.feed("second chunk</root>")
    #   parser.finish
    #
    # Events are delivered to +listener+ exactly like
    # REXML::Parsers::StreamParser does (see REXML::StreamListener)
    # and in the same order.  A chunk may end anywhere: in the middle
    # of a tag, an attribute value, an entity reference or even a
    # multi-byte character.  Incomplete data is never reported as
    # malformed XML; the parser simply waits for the next #feed.
    # Malformed input raises REXML::ParseException as soon as it is
    # detected, and #finish raises REXML::ParseException when the
    # document is incomplete.  Feeding after #finish raises IOError.
    class FeedParser
      def initialize(listener, encoding=nil)
        @listener = listener
        @source = FeedSource.new(encoding)
        @parser = BaseParser.new(@source)
        @entities = {}
        @fiber = nil
        @error = nil
      end

      def add_listener( listener )
        @parser.add_listener( listener )
      end

      def entity_expansion_count
        @parser.entity_expansion_count
      end

      def entity_expansion_limit=( limit )
        @parser.entity_expansion_limit = limit
      end

      def entity_expansion_text_limit=( limit )
        @parser.entity_expansion_text_limit = limit
      end

      # Feeds a chunk of XML.  Events completed by the chunk are
      # reported to the listener before this method returns.  Returns
      # self so calls can be chained.
      def feed( data )
        raise IOError, "cannot feed after finish" if @source.finished?
        raise @error if @error
        @source.feed(data)
        resume_parser
        self
      end

      # Marks the input as complete and parses any remaining buffered
      # data.  Raises REXML::ParseException when the document is
      # incomplete or malformed.
      def finish
        raise @error if @error
        unless @source.finished?
          @source.finish
          resume_parser
        end
        nil
      end

      def finished?
        @source.finished?
      end

      private

      def resume_parser
        return if @fiber && !@fiber.alive?
        unless @fiber
          @fiber = Fiber.new { parse }
          @source.parser_fiber = @fiber
        end
        @fiber.resume
      rescue Exception => error
        @error = error
        raise
      end

      def parse
        while true
          event = @parser.pull
          case event[0]
          when :end_document
            return
          when :start_element
            attrs = event[2].each do |n, v|
              event[2][n] = @parser.unnormalize( v )
            end
            @listener.tag_start( event[1], attrs )
          when :end_element
            @listener.tag_end( event[1] )
          when :text
            unnormalized = @parser.unnormalize( event[1], @entities )
            @listener.text( unnormalized )
          when :processing_instruction
            @listener.instruction( *event[1,2] )
          when :start_doctype
            @listener.doctype( *event[1..-1] )
          when :end_doctype
            # FIXME: remove this condition for milestone:3.2
            @listener.doctype_end if @listener.respond_to? :doctype_end
          when :comment, :attlistdecl, :cdata, :xmldecl, :elementdecl
            @listener.send( event[0].to_s, *event[1..-1] )
          when :entitydecl, :notationdecl
            @entities[ event[1] ] = event[2] if event.size == 3
            @listener.send( event[0].to_s, event[1..-1] )
          when :externalentity
            entity_reference = event[1]
            content = entity_reference.gsub(/\A%|;\z/, "")
            @listener.entity(content)
          end
        end
      end
    end
  end
end
