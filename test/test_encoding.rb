# coding: utf-8
# frozen_string_literal: false

require 'rexml/source'
require 'rexml/document'

module REXMLTests
  class ChunkedIO
    def initialize(data, chunk_size)
      @io = StringIO.new(data)
      @chunk_size = chunk_size
    end

    def binmode
      self
    end

    def set_encoding(*)
      @io.binmode
    end

    def external_encoding
      ::Encoding::BINARY
    end

    def eof?
      @io.eof?
    end

    def read(length = nil)
      @io.read(length || @chunk_size)
    end

    def readline(separator = nil)
      result = +""
      until @io.eof? || (separator && result.include?(separator.b))
        result << @io.read(@chunk_size).to_s
      end
      result
    end
  end

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

    def test_parse_utf32_across_read_chunks
      xml = <<~XML.chomp
        <?xml version="1.0" encoding="UTF-32"?>
        <root attr="&#128169;">&amp; &#x1F600;</root>
      XML

      ["UTF-32BE", "UTF-32LE"].each do |encoding|
        data = xml.encode(encoding).b
        assert_nothing_raised do
          REXML::Document.new(data)
          REXML::Document.new(StringIO.new(data))
        end
        [1, 4, 5, 7].each do |chunk_size|
          doc = REXML::Document.new(ChunkedIO.new(data, chunk_size))

          assert_equal("UTF-32", doc.encoding)
          assert_equal("\u{1F4A9}", doc.root.attributes["attr"])
          assert_equal("& \u{1F600}", doc.root.text)

          output = +""
          doc.write(output)
          assert_equal(::Encoding::UTF_32BE, output.encoding)
          assert_equal([0x00, 0x00, 0xFE, 0xFF], output.bytes.first(4))
          assert_predicate(output, :valid_encoding?)

          reparsed = REXML::Document.new(StringIO.new(output))
          assert_equal("& \u{1F600}", reparsed.root.text)
        end
      end
    end

    def test_write_utf32_with_explicit_byte_order
      xml = %q{<?xml version='1.0'?><root attr='&#128169;'>&#x1F600;</root>}

      expected = {
        "UTF-32BE" => [0x00, 0x00, 0x00, 0x3C],
        "UTF-32LE" => [0x3C, 0x00, 0x00, 0x00],
      }
      expected.each do |encoding, first_bytes|
        doc = REXML::Document.new(xml)
        doc.xml_decl.encoding = encoding
        output = +""
        doc.write(output)

        assert_equal(::Encoding.find(encoding), output.encoding)
        assert_equal(first_bytes, output.bytes.first(4))
        assert_not_equal([0x00, 0x00, 0xFE, 0xFF], output.bytes.first(4))
        assert_not_equal([0xFF, 0xFE, 0x00, 0x00], output.bytes.first(4))
        assert_predicate(output, :valid_encoding?)

        reparsed = REXML::Document.new(StringIO.new(output))
        assert_equal("\u{1F600}", reparsed.root.text)
        assert_equal("\u{1F4A9}", reparsed.root.attributes["attr"])
      end
    end

    def test_parse_utf32_without_bom_uses_external_encoding
      ["UTF-32BE", "UTF-32LE"].each do |encoding|
        data = <<~XML.chomp.encode(encoding).b
          <?xml version="1.0" encoding="#{encoding}"?>
          <root>\u{1F600}</root>
        XML
        source = REXML::Source.new(data, encoding)
        doc = REXML::Document.new(source)

        assert_equal("\u{1F600}", doc.root.text)
      end
    end

    def test_parse_utf32_without_bom_uses_generic_external_encoding
      ["UTF-32BE", "UTF-32LE"].each do |encoding|
        data = %q{<root>&#x1F600;</root>}.encode(encoding).b
        source = REXML::IOSource.new(StringIO.new(data), 500, "UTF-32")
        doc = REXML::Document.new(source)

        assert_equal("\u{1F600}", doc.root.text)
      end
    end

    def test_parse_utf32_without_bom_detects_byte_order
      xml = <<~XML.chomp
        <?xml version="1.0" encoding="UTF-32"?>
        <root>&#x1F600;</root>
      XML

      ["UTF-32BE", "UTF-32LE"].each do |encoding|
        data = xml.encode(encoding).b
        doc = REXML::Document.new(StringIO.new(data))

        assert_equal("UTF-32", doc.encoding)
        assert_equal("\u{1F600}", doc.root.text)
      end
    end

    def test_utf32_bom_conflicts_with_xml_encoding_declaration
      declaration = %q{<?xml version="1.0" encoding="UTF-32BE"?><root/>}
      data = "\xFF\xFE\x00\x00".b + declaration.encode("UTF-32LE").b

      exception = assert_raise(REXML::ParseException) do
        REXML::Document.new(StringIO.new(data))
      end
      assert_kind_of(ArgumentError, exception.continued_exception)
    end

    def test_utf32_byte_order_conflicts_without_bom
      declaration = %q{<?xml version="1.0" encoding="UTF-32LE"?>}
      data = (declaration + "<root/>").encode("UTF-32BE").b

      exception = assert_raise(REXML::ParseException) do
        REXML::Document.new(StringIO.new(data))
      end
      assert_kind_of(ArgumentError, exception.continued_exception)
    end

    def test_utf32_bom_conflicts_with_external_encoding
      data = "\x00\x00\xFE\xFF".b + "<root/>".encode("UTF-32BE").b

      assert_raise(ArgumentError) do
        REXML::Source.new(data, "UTF-32LE")
      end
    end

    def test_utf32_rejects_truncated_codepoint_across_read_chunks
      data = <<~XML.chomp.encode("UTF-32BE").b
        <?xml version="1.0" encoding="UTF-32"?><root>\u{1F600}</root>
      XML

      [1, 2, 3].each do |truncated_bytes|
        exception = assert_raise(REXML::ParseException) do
          REXML::Document.new(ChunkedIO.new(data.byteslice(0, data.bytesize - truncated_bytes), 1))
        end
        assert_kind_of(::Encoding::InvalidByteSequenceError,
                       exception.continued_exception)
      end
    end

    def test_utf32_rejects_illegal_unicode_values
      declaration = %q{<?xml version="1.0" encoding="UTF-32BE"?>}.encode("UTF-32BE").b
      illegal_codepoint = [0x00, 0x00, 0xDB, 0x80].pack("C4")
      data = declaration + "<root>".encode("UTF-32BE").b +
        illegal_codepoint + "</root>".encode("UTF-32BE").b

      exception = assert_raise(REXML::ParseException) do
        REXML::Document.new(ChunkedIO.new(data, 1))
      end
      assert_kind_of(::Encoding::InvalidByteSequenceError,
                     exception.continued_exception)
    end
  end
end
