# coding: utf-8
# frozen_string_literal: false

require 'rexml/source'
require 'rexml/document'

module REXMLTests
  class EncodingTester < Test::Unit::TestCase
    include Helper::Fixture
    include Helper::Global
    include REXML

    def setup
      @encoded_root = "<a><b>\346</b></a>"
      @encoded = "<?xml version='1.0' encoding='ISO-8859-3'?>"+
        @encoded_root
      @not_encoded = "<a><b>ĉ</b></a>"
    end

    # Given an encoded document, try to write out to that encoding
    def test_encoded_in_encoded_out
      doc = Document.new( @encoded )
      doc.write( out="" )
      out.force_encoding(::Encoding::ASCII_8BIT)
      assert_equal( @encoded.b, out )
    end

    # Given an encoded document, try to change the encoding and write it out
    def test_encoded_in_change_out
      doc = Document.new( @encoded )
      doc.xml_decl.encoding = "UTF-8"
      assert_equal("UTF-8", doc.encoding)
      REXML::Formatters::Default.new.write( doc.root, out="" )
      out.force_encoding(::Encoding::ASCII_8BIT)
      assert_equal( @not_encoded.b, out )
      char = XPath.first( doc, "/a/b/text()" ).to_s
      char.force_encoding(::Encoding::ASCII_8BIT)
      assert_equal( "ĉ".b, char )
    end

    # * Given an encoded document, try to write it to a different encoding
    def test_encoded_in_different_out
      doc = Document.new( @encoded )
      REXML::Formatters::Default.new.write( doc.root, Output.new( out="", "UTF-8" ) )
      out.force_encoding(::Encoding::ASCII_8BIT)
      assert_equal( @not_encoded.b, out )
    end

    # * Given a non-encoded document, change the encoding
    def test_in_change_out
      doc = Document.new( @not_encoded )
      doc.xml_decl.encoding = "ISO-8859-3"
      assert_equal("ISO-8859-3", doc.encoding)
      doc.write( out="" )
      out.force_encoding(::Encoding::ASCII_8BIT)
      assert_equal( @encoded.b, out )
    end

    # * Given a non-encoded document, write to a different encoding
    def test_in_different_out
      doc = Document.new( @not_encoded )
      doc.write( Output.new( out="", "ISO-8859-3" ) )
      out.force_encoding(::Encoding::ASCII_8BIT)
      assert_equal( "<?xml version='1.0'?>#{@encoded_root}".b, out )
    end

    # * Given an encoded document, accessing text and attribute nodes
    #   should provide UTF-8 text.
    def test_in_different_access
      doc = Document.new <<~EOL
      <?xml version='1.0' encoding='ISO-8859-1'?>
      <a a="\xFF">\xFF</a>
      EOL
      expect = "\303\277"
      expect.force_encoding(::Encoding::UTF_8)
      assert_equal( expect, doc.elements['a'].attributes['a'] )
      assert_equal( expect, doc.elements['a'].text )
    end


    def test_ticket_89
      doc = Document.new <<~EOL
         <?xml version="1.0" encoding="CP-1252" ?>
         <xml><foo></foo></xml>
         EOL

      REXML::Document.new doc
    end

    def test_parse_utf16
      utf16 = File.open(fixture_path("utf16.xml")) do |f|
        REXML::Document.new(f)
      end
      assert_equal("UTF-16", utf16.encoding)
      assert( utf16[0].kind_of?(REXML::XMLDecl))
    end

    def test_parse_utf16_with_utf8_default_internal
      with_default_internal("UTF-8") do
        utf16 = File.open(fixture_path("utf16.xml")) do |f|
          REXML::Document.new(f)
        end
        assert_equal("UTF-16", utf16.encoding)
      end
    end
  end

  class UTF32EncodingTest < Test::Unit::TestCase
    include REXML

    XML_CONTENT = "<?xml version='1.0' encoding='UTF-32'?>" +
                  "<root a='v\u{1F600}'>t\u{20000}&amp;&lt;</root>"

    def encode_document(encoding, bom: true, declaration_encoding: "UTF-32",
                        content: nil)
      xml = content || XML_CONTENT.sub("UTF-32", declaration_encoding)
      body = xml.encode(encoding)
      bom ? "\ufeff".encode(encoding) + body : body
    end

    def assert_parseable(document_bytes)
      doc = Document.new(document_bytes)
      assert_equal("v\u{1F600}", doc.root.attributes["a"])
      assert_equal("t\u{20000}&<", doc.root.text)
      doc
    end

    def test_parse_utf32be_with_bom
      doc = assert_parseable(encode_document("UTF-32BE"))
      assert_equal("UTF-32", doc.encoding)
    end

    def test_parse_utf32le_with_bom
      doc = assert_parseable(encode_document("UTF-32LE"))
      assert_equal("UTF-32", doc.encoding)
    end

    def test_parse_utf32be_without_bom
      doc = assert_parseable(encode_document("UTF-32BE", bom: false,
                                             declaration_encoding: "UTF-32BE"))
      assert_equal("UTF-32BE", doc.encoding)
    end

    def test_parse_utf32le_without_bom
      doc = assert_parseable(encode_document("UTF-32LE", bom: false,
                                             declaration_encoding: "UTF-32LE"))
      assert_equal("UTF-32LE", doc.encoding)
    end

    def test_parse_utf32_from_io
      assert_parseable(StringIO.new(encode_document("UTF-32BE")))
      assert_parseable(StringIO.new(encode_document("UTF-32LE")))
    end

    def test_parse_utf32_codepoints_across_read_blocks
      content = "<?xml version='1.0' encoding='UTF-32'?><root>" +
                "\u{1F600}\u{20000}x" * 2000 +
                "</root>"
      bytes = encode_document("UTF-32LE", content: content)
      doc = Document.new(StringIO.new(bytes))
      assert_equal("\u{1F600}\u{20000}x" * 2000, doc.root.text)
    end

    def test_parse_utf32_external_encoding_without_bom
      ["UTF-32BE", "UTF-32LE"].each do |encoding|
        bytes = encode_document(encoding, bom: false)
        source = IOSource.new(StringIO.new(bytes), 500, encoding)
        doc = Document.new(source)
        assert_equal("UTF-32", doc.encoding)
        assert_equal("t\u{20000}&<", doc.root.text)
      end
    end

    def test_parse_utf32_truncated
      bytes = encode_document("UTF-32BE")
      assert_raise(REXML::ParseException,
                   ::Encoding::InvalidByteSequenceError) do
        Document.new(bytes[0..-3])
      end
      assert_raise(REXML::ParseException,
                   ::Encoding::InvalidByteSequenceError) do
        Document.new(StringIO.new(bytes[0..-3]))
      end
    end

    def test_parse_utf32_invalid_codepoint
      prolog = "<?xml version='1.0'?><root>".encode("UTF-32BE")
      epilog = "</root>".encode("UTF-32BE")
      [0x110000, 0xD800].each do |codepoint|
        bytes = "\ufeff".encode("UTF-32BE") + prolog +
                [codepoint].pack("N").force_encoding("UTF-32BE") + epilog
        assert_raise(REXML::ParseException,
                     ::Encoding::InvalidByteSequenceError) do
          Document.new(bytes)
        end
      end
    end

    def test_parse_utf32_conflicting_declaration
      ["UTF-8", "UTF-16", "UTF-32LE"].each do |declaration_encoding|
        bytes = encode_document("UTF-32BE",
                                declaration_encoding: declaration_encoding)
        error = assert_raise(REXML::ParseException) do
          Document.new(bytes)
        end
        assert_match(/conflicts/, error.message)
      end
    end

    def test_write_utf32_round_trip
      ["UTF-32BE", "UTF-32LE"].each do |encoding|
        doc = assert_parseable(encode_document(encoding))
        out = +""
        doc.write(out)
        out.force_encoding(::Encoding::ASCII_8BIT)
        # A bare "UTF-32" declaration is written in big-endian with a BOM,
        # mirroring how "UTF-16" is written as UTF-16BE with a BOM.
        assert_equal("\ufeff".encode("UTF-32BE").b, out[0, 4].b)
        reparsed = assert_parseable(out)
        assert_equal("UTF-32", reparsed.encoding)
      end
    end

    def test_write_utf32le_keeps_byte_order
      doc = assert_parseable(encode_document("UTF-32LE", bom: false,
                                             declaration_encoding: "UTF-32LE"))
      out = +""
      doc.write(out)
      out.force_encoding(::Encoding::ASCII_8BIT)
      assert_equal("\ufeff".encode("UTF-32LE").b, out[0, 4].b)
      assert_include(out.encode(::Encoding::UTF_8, ::Encoding::UTF_32LE),
                     "encoding='UTF-32LE'")
      reparsed = assert_parseable(out)
      assert_equal("UTF-32LE", reparsed.encoding)
    end
  end
end
