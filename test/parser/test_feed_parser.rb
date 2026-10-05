# frozen_string_literal: false
require "test/unit"
require "rexml/document"
require "rexml/streamlistener"

module REXMLTests
  class TestFeedParser < Test::Unit::TestCase
    class RecordingListener
      include REXML::StreamListener
      attr_reader :events
      def initialize
        @events = []
      end
      def tag_start(name, attributes)
        @events << [:tag_start, name, attributes.dup]
      end
      def tag_end(name)
        @events << [:tag_end, name]
      end
      def text(text)
        @events << [:text, text]
      end
      def xmldecl(version, encoding, standalone)
        @events << [:xmldecl, version, encoding, standalone]
      end
      def comment(content)
        @events << [:comment, content]
      end
      def cdata(content)
        @events << [:cdata, content]
      end
      def instruction(name, content)
        @events << [:processing_instruction, name, content]
      end
      def doctype(name, pub_sys, long_name, uri)
        @events << [:doctype, name, pub_sys, long_name, uri]
      end
      def doctype_end
        @events << [:doctype_end]
      end
      def method_missing(name, *arguments)
        @events << [name, *arguments]
      end
      def respond_to_missing?(name, include_private=false)
        true
      end
    end

    XML = <<~XML
      <?xml version="1.0"?>
      <root xmlns:n="http://example.com/">
        <!-- a comment -->
        <n:item n:id="a&amp;b">héllo</n:item>
        <![CDATA[<raw>&data]]>
        <?pi target?>
      </root>
    XML


    def feed_in_chunks(xml, chunk_size)
      listener = RecordingListener.new
      parser = REXML::Parsers::FeedParser.new(listener)
      bytes = xml.b
      offset = 0
      while offset < bytes.bytesize
        parser.feed(bytes.byteslice(offset, chunk_size))
        offset += chunk_size
      end
      parser.finish
      [parser, listener]
    end

    def reference_events(xml)
      listener = RecordingListener.new
      REXML::Document.parse_stream(xml, listener)
      listener.events
    end

    def test_single_feed
      parser, listener = feed_in_chunks(XML, XML.bytesize)
      assert_equal(reference_events(XML), listener.events)
      assert_true(parser.finished?)
    end

    def test_initial_data
      listener = RecordingListener.new
      parser = REXML::Parsers::FeedParser.new(listener, XML)
      parser.finish
      assert_equal(reference_events(XML), listener.events)
    end

    def test_document_entry_point
      listener = RecordingListener.new
      parser = REXML::Document.feed_parser(listener)
      parser.feed("<root/>")
      parser.finish
      assert_equal([[:tag_start, "root", {}], [:tag_end, "root"]],
                   listener.events)
    end

    def test_split_every_byte
      parser, listener = feed_in_chunks("<root a='v&amp;x'/>", 1)
      expected = [
        [:tag_start, "root", {"a" => "v&x"}],
        [:tag_end, "root"],
      ]
      assert_equal(expected, listener.events)
      assert_true(parser.finished?)
    end

    def test_event_order_matches_stream_parser
      [1, 2, 3, 4, 5, 7, 13, 64, XML.bytesize].each do |chunk_size|
        parser, listener = feed_in_chunks(XML, chunk_size)
        assert_equal(reference_events(XML), listener.events,
                     "events differ for chunk size #{chunk_size}")
        assert_true(parser.finished?)
      end
    end

    def test_split_tag_name
      listener = RecordingListener.new
      parser = REXML::Parsers::FeedParser.new(listener)
      parser.feed("<roo")
      assert_equal([], listener.events)
      parser.feed("t>text</ro")
      assert_equal([[:tag_start, "root", {}], [:text, "text"]],
                   listener.events)
      parser.feed("ot>")
      parser.finish
      assert_equal([:tag_end, "root"], listener.events.last)
    end

    def test_split_attribute_quote
      listener = RecordingListener.new
      parser = REXML::Parsers::FeedParser.new(listener)
      parser.feed(%q{<root a="va})
      parser.feed(%q{lue">ok</root>})
      parser.finish
      assert_equal([:tag_start, "root", {"a" => "value"}],
                   listener.events.first)
    end

    def test_split_quote_alone
      listener = RecordingListener.new
      parser = REXML::Parsers::FeedParser.new(listener)
      parser.feed(%q{<root a=})
      assert_equal([], listener.events)
      parser.feed(%q{"v"})
      assert_equal([], listener.events)
      parser.feed(%q{/>})
      parser.finish
      assert_equal([:tag_start, "root", {"a" => "v"}],
                   listener.events.first)
    end

    def test_split_entity_reference
      listener = RecordingListener.new
      parser = REXML::Parsers::FeedParser.new(listener)
      ["<r>a", "&amp", ";b&lt;", ";c</r>"].each do |chunk|
        parser.feed(chunk)
      end
      parser.finish
      assert_equal([:text, "a&b<;c"], listener.events[1])
    end

    def test_split_entity_reference_byte_by_byte
      parser, listener = feed_in_chunks("<r>&amp;</r>", 1)
      assert_equal([[:tag_start, "r", {}],
                    [:text, "&"],
                    [:tag_end, "r"]], listener.events)
    end

    def test_split_utf8_character
      xml = "<r>あいう</r>"
      parser, listener = feed_in_chunks(xml, 1)
      assert_equal([:text, "あいう"], listener.events[1])
    end

    def test_split_utf8_four_byte_character
      xml = "<r>\u{1F600}</r>"
      parser, listener = feed_in_chunks(xml, 1)
      assert_equal([:text, "\u{1F600}"], listener.events[1])
    end

    def test_incomplete_input_is_not_an_error
      listener = RecordingListener.new
      parser = REXML::Parsers::FeedParser.new(listener)
      assert_nothing_raised do
        parser.feed("<?xml vers")
        parser.feed("ion=\"1.0\"")
        parser.feed("?><ro")
        parser.feed("ot><!-- par")
        parser.feed("tial --><a x=\"y")
        parser.feed("&amp;")
      end
      parser.feed(%q{;z">x</a></root>})
      parser.finish
      assert_true(parser.finished?)
    end

    def test_malformed_input_is_reported_immediately
      listener = RecordingListener.new
      parser = REXML::Parsers::FeedParser.new(listener)
      parser.feed("<root>")
      error = assert_raise(REXML::ParseException) do
        parser.feed(%q{<bad @>})
      end
      assert_match(/attribute name|malformed|invalid/i, error.message)
    end

    def test_truncated_document_is_reported_at_finish
      parser = REXML::Parsers::FeedParser.new(RecordingListener.new)
      parser.feed("<root><sub>")
      error = assert_raise(REXML::ParseException) do
        parser.finish
      end
      assert_match(/Missing end tag/, error.message)
    end

    def test_truncated_attribute_is_reported_at_finish
      parser = REXML::Parsers::FeedParser.new(RecordingListener.new)
      parser.feed("<root a='x")
      assert_nothing_raised { parser }
      error = assert_raise(REXML::ParseException) do
        parser.finish
      end
      assert_match(/end quote/, error.message)
    end

    def test_no_root_at_finish
      parser = REXML::Parsers::FeedParser.new(RecordingListener.new)
      parser.feed("   \n")
      assert_raise(REXML::ParseException) do
        parser.finish
      end
    end

    def test_no_feed_after_finish
      parser = REXML::Parsers::FeedParser.new(RecordingListener.new)
      parser.feed("<root/>")
      parser.finish
      assert_raise(IOError) { parser.feed("<more/>") }
      assert_raise(IOError) { parser.finish }
    end

    def test_finish_twice
      parser = REXML::Parsers::FeedParser.new(RecordingListener.new)
      parser.feed("<root/>")
      parser.finish
      assert_raise(IOError) { parser.finish }
    end

    def test_empty_feeds
      listener = RecordingListener.new
      parser = REXML::Parsers::FeedParser.new(listener)
      parser.feed("")
      parser.feed("<root/>")
      parser.feed("")
      parser.finish
      assert_equal([[:tag_start, "root", {}], [:tag_end, "root"]],
                   listener.events)
    end

    def test_events_are_not_emitted_speculatively
      events = []
      listener = Object.new
      listener.define_singleton_method(:tag_start) { |*a| events << a }
      listener.define_singleton_method(:tag_end) { |*a| events << a }
      parser = REXML::Parsers::FeedParser.new(listener)
      parser.feed("<root a='x</root>")
      assert_equal([], events)
      parser.feed("'/>").finish
      assert_equal([["root", {"a" => "x</root>"}], ["root"]], events)
    end

    def test_split_cdata
      parser, listener = feed_in_chunks("<r><![CDATA[a<b>&c]]></r>", 1)
      assert_include(listener.events, [:cdata, "a<b>&c"])
    end

    def test_split_processing_instruction
      parser, listener = feed_in_chunks("<r><?app data?></r>", 1)
      assert_include(listener.events, [:processing_instruction, "app", "data"])
    end

    def test_bom_is_accepted
      listener = RecordingListener.new
      parser = REXML::Parsers::FeedParser.new(listener)
      bom = "\xEF\xBB\xBF".b
      parser.feed(bom)
      parser.feed("<root/>")
      parser.finish
      assert_equal([[:tag_start, "root", {}], [:tag_end, "root"]],
                   listener.events)
    end

    def test_split_bom
      listener = RecordingListener.new
      parser = REXML::Parsers::FeedParser.new(listener)
      bom = "\xEF\xBB\xBF".b
      parser.feed(bom.byteslice(0, 1))
      parser.feed(bom.byteslice(1, 2))
      parser.feed("<root/>")
      parser.finish
      assert_equal([[:tag_start, "root", {}], [:tag_end, "root"]],
                   listener.events)
    end
  end
end
