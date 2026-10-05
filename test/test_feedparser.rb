# frozen_string_literal: false

require_relative "helper"
require "rexml/parsers/feedparser"

module REXMLTests
  class FeedParserTest < Test::Unit::TestCase
    class Recorder
      attr_reader :events
      def initialize
        @events = []
      end
      def method_missing(name, *args)
        @events << [name, *args]
      end
      def respond_to_missing?(name, include_private=false)
        true
      end
    end

    def stream_events(xml)
      listener = Recorder.new
      REXML::Document.parse_stream(xml, listener)
      listener.events
    end

    def feed_events(xml, chunk_size)
      listener = Recorder.new
      parser = REXML::Parsers::FeedParser.new(listener)
      xml.scan(/.{1,#{chunk_size}}/m).each { |chunk| parser.feed(chunk) }
      parser.finish
      listener.events
    end

    SIMPLE_XML = <<-XML
<?xml version="1.0"?>
<root a="1" b='2'>
  text &amp; &#65;
  <child x="v">inner</child>
  <empty/>
</root>
    XML

    FULL_XML = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<!-- a comment -->
<?target instruction?>
<!DOCTYPE root [
  <!ENTITY ent "expanded">
  <!ELEMENT root (#PCDATA)>
  <!ATTLIST root id CDATA #IMPLIED>
  <!NOTATION n1 SYSTEM "urn:x-test">
]>
<root a="1&amp;2" b='single'>
  text &ent; &amp; &#65; \u65e5\u672c\u8a9e
  <child><![CDATA[cdata <not-a-tag>]]></child>
  <?another pi?>
  <!-- another comment -->
</root>
    XML

    def test_simple_document_events_match_stream_parser
      expected = stream_events(SIMPLE_XML)
      [1, 2, 3, 5, 7, 16, 1000].each do |chunk_size|
        assert_equal(expected, feed_events(SIMPLE_XML, chunk_size),
                     "chunk size #{chunk_size}")
      end
    end

    def test_full_document_events_match_stream_parser
      expected = stream_events(FULL_XML)
      [1, 2, 3, 5, 7, 16, 1000].each do |chunk_size|
        assert_equal(expected, feed_events(FULL_XML, chunk_size),
                     "chunk size #{chunk_size}")
      end
    end

    def test_random_chunkings_produce_identical_events
      expected = stream_events(FULL_XML)
      random = Random.new(42)
      20.times do
        listener = Recorder.new
        parser = REXML::Parsers::FeedParser.new(listener)
        pos = 0
        while pos < FULL_XML.bytesize
          size = 1 + random.rand(8)
          parser.feed(FULL_XML.byteslice(pos, size))
          pos += size
        end
        parser.finish
        assert_equal(expected, listener.events)
      end
    end

    def test_split_inside_tag_name
      listener = Recorder.new
      parser = REXML::Parsers::FeedParser.new(listener)
      parser.feed("<ro")
      parser.feed("ot>")
      parser.feed("</ro")
      parser.feed("ot>")
      parser.finish
      assert_equal(stream_events("<root></root>"), listener.events)
    end

    def test_split_inside_attribute_quote_and_entity
      listener = Recorder.new
      parser = REXML::Parsers::FeedParser.new(listener)
      parser.feed("<a x='va")
      parser.feed("l&amp;1")
      parser.feed("2'>t</a>")
      parser.finish
      assert_equal([[:tag_start, "a", {"x" => "val&12"}],
                    [:text, "t"],
                    [:tag_end, "a"]],
                   listener.events)
    end

    def test_split_inside_multibyte_character
      xml = "<a>\u65e5\u672c</a>"
      expected = stream_events(xml)
      listener = Recorder.new
      parser = REXML::Parsers::FeedParser.new(listener)
      xml.each_byte do |byte|
        parser.feed(byte.chr.b)
      end
      parser.finish
      assert_equal(expected, listener.events)
    end

    def test_events_are_delivered_before_finish
      listener = Recorder.new
      parser = REXML::Parsers::FeedParser.new(listener)
      parser.feed(SIMPLE_XML)
      assert_equal(stream_events(SIMPLE_XML), listener.events)
    end

    def test_utf8_bom
      listener = Recorder.new
      parser = REXML::Parsers::FeedParser.new(listener)
      parser.feed("\xEF\xBB\xBF".b)
      parser.feed("<a/>")
      parser.finish
      assert_equal([[:tag_start, "a", {}], [:tag_end, "a"]],
                   listener.events)
    end

    def test_utf16le_with_bom_byte_by_byte
      xml = "\xFF\xFE".b + "<a>\u65e5\u672c</a>".encode("UTF-16LE").b
      listener = Recorder.new
      parser = REXML::Parsers::FeedParser.new(listener)
      xml.each_byte do |byte|
        parser.feed(byte.chr.b)
      end
      parser.finish
      assert_equal([[:tag_start, "a", {}],
                    [:text, "\u65e5\u672c"],
                    [:tag_end, "a"]],
                   listener.events)
    end

    def test_mismatched_end_tag_is_reported_while_feeding
      parser = REXML::Parsers::FeedParser.new(Recorder.new)
      error = assert_raise(REXML::ParseException) do
        parser.feed("<a><b></a>")
      end
      assert_match(/Missing end tag/, error.message)
    end

    def test_invalid_attribute_is_reported
      parser = REXML::Parsers::FeedParser.new(Recorder.new)
      assert_raise(REXML::ParseException) do
        parser.feed("<a 9='x'>")
        parser.finish
      end
    end

    def test_missing_end_tag_is_reported_at_finish
      parser = REXML::Parsers::FeedParser.new(Recorder.new)
      parser.feed("<a>")
      error = assert_raise(REXML::ParseException) do
        parser.finish
      end
      assert_match(/Missing end tag/, error.message)
    end

    def test_unclosed_comment_is_reported_at_finish
      parser = REXML::Parsers::FeedParser.new(Recorder.new)
      parser.feed("<a><!-- oops</a>")
      assert_raise(REXML::ParseException) do
        parser.finish
      end
    end

    def test_no_root_element_is_reported_at_finish
      parser = REXML::Parsers::FeedParser.new(Recorder.new)
      assert_raise(REXML::ParseException) do
        parser.finish
      end
    end

    def test_extra_content_after_root_is_reported
      parser = REXML::Parsers::FeedParser.new(Recorder.new)
      parser.feed("<a/>")
      parser.feed("junk")
      assert_raise(REXML::ParseException) do
        parser.finish
      end
    end

    def test_feed_after_finish_raises
      parser = REXML::Parsers::FeedParser.new(Recorder.new)
      parser.feed("<a/>")
      parser.finish
      assert_raise(IOError) do
        parser.feed("<b/>")
      end
    end

    def test_finish_is_idempotent
      parser = REXML::Parsers::FeedParser.new(Recorder.new)
      parser.feed("<a/>")
      parser.finish
      assert_nothing_raised do
        parser.finish
      end
    end

    def test_feed_returns_self_for_chaining
      parser = REXML::Parsers::FeedParser.new(Recorder.new)
      assert_same(parser, parser.feed("<a/>"))
    end

    def test_entity_expansion_count
      xml = "<!DOCTYPE a [<!ENTITY e 'v'>]><a>&e;</a>"
      parser = REXML::Parsers::FeedParser.new(Recorder.new)
      parser.feed(xml)
      parser.finish
      assert_equal(1, parser.entity_expansion_count)
    end
  end
end
