# frozen_string_literal: false

require "rexml/document"
require "rexml/validation/dtd_validator"

module REXMLTests
  class DTDValidatorTest < Test::Unit::TestCase
    def validate(dtd, xml)
      validator = REXML::Validation::DTDValidator.new(dtd)
      validator.validate(REXML::Document.new(xml))
    end

    def assert_valid(dtd, xml)
      assert_true(validate(dtd, xml))
    end

    def assert_invalid(dtd, xml)
      assert_raise(REXML::Validation::ValidationException) do
        validate(dtd, xml)
      end
    end

    def test_empty
      dtd = "<!ELEMENT a EMPTY>"
      assert_valid(dtd, "<a/>")
      assert_valid(dtd, "<a></a>")
      assert_valid(dtd, "<a>  \n  </a>")
      assert_invalid(dtd, "<a>x</a>")
      assert_invalid(dtd, "<a><b/></a>")
    end

    def test_any
      dtd = "<!ELEMENT a ANY><!ELEMENT b EMPTY>"
      assert_valid(dtd, "<a/>")
      assert_valid(dtd, "<a>text<b/>more</a>")
    end

    def test_mixed_pcdata_only
      dtd = "<!ELEMENT a (#PCDATA)>"
      assert_valid(dtd, "<a/>")
      assert_valid(dtd, "<a>hello &lt;world&gt;</a>")
      assert_valid(dtd, "<a><![CDATA[cdata text]]></a>")
      assert_invalid(dtd, "<a><b/></a>")
    end

    def test_mixed_with_names
      dtd = "<!ELEMENT a (#PCDATA|b|c)*>" \
            "<!ELEMENT b EMPTY><!ELEMENT c EMPTY>"
      assert_valid(dtd, "<a>x<b/>y<c/>z</a>")
      assert_valid(dtd, "<a><b/><b/></a>")
      assert_invalid(dtd, "<a><d/></a>")
    end

    def test_sequence
      dtd = "<!ELEMENT a (b,c)><!ELEMENT b EMPTY><!ELEMENT c EMPTY>"
      assert_valid(dtd, "<a><b/><c/></a>")
      assert_valid(dtd, "<a>\n  <b/>\n  <c/>\n</a>")
      assert_invalid(dtd, "<a><c/><b/></a>")
      assert_invalid(dtd, "<a><b/></a>")
      assert_invalid(dtd, "<a><b/><c/><c/></a>")
    end

    def test_choice
      dtd = "<!ELEMENT a (b|c)><!ELEMENT b EMPTY><!ELEMENT c EMPTY>"
      assert_valid(dtd, "<a><b/></a>")
      assert_valid(dtd, "<a><c/></a>")
      assert_invalid(dtd, "<a/>")
      assert_invalid(dtd, "<a><b/><c/></a>")
    end

    def test_quantifiers
      dtd = "<!ELEMENT a (b?,c*,d+)>" \
            "<!ELEMENT b EMPTY><!ELEMENT c EMPTY><!ELEMENT d EMPTY>"
      assert_valid(dtd, "<a><d/></a>")
      assert_valid(dtd, "<a><b/><c/><c/><d/><d/></a>")
      assert_invalid(dtd, "<a><b/><b/></a>")
      assert_invalid(dtd, "<a><c/></a>")
    end

    def test_nested_groups
      dtd = "<!ELEMENT a ((b|c)+,d?)>" \
            "<!ELEMENT b EMPTY><!ELEMENT c EMPTY><!ELEMENT d EMPTY>"
      assert_valid(dtd, "<a><b/><c/><b/><d/></a>")
      assert_valid(dtd, "<a><c/></a>")
      assert_invalid(dtd, "<a><d/></a>")
      assert_invalid(dtd, "<a><b/><d/><d/></a>")
    end

    def test_group_repetition
      dtd = "<!ELEMENT a (b,c)*><!ELEMENT b EMPTY><!ELEMENT c EMPTY>"
      assert_valid(dtd, "<a/>")
      assert_valid(dtd, "<a><b/><c/><b/><c/></a>")
      assert_invalid(dtd, "<a><b/></a>")
      assert_invalid(dtd, "<a><c/></a>")
    end

    def test_comments_and_processing_instructions_are_ignored
      dtd = "<!ELEMENT a (b)><!ELEMENT b EMPTY>"
      assert_valid(dtd, "<a><!-- comment --><?pi data?><b/></a>")
    end

    def test_non_whitespace_text_in_element_content
      dtd = "<!ELEMENT a (b)><!ELEMENT b EMPTY>"
      assert_invalid(dtd, "<a>text<b/></a>")
      assert_invalid(dtd, "<a><b/>text</a>")
      assert_invalid(dtd, "<a><![CDATA[text]]><b/></a>")
    end

    def test_error_reports_path_actual_node_and_expected
      dtd = "<!ELEMENT root (item+)>" \
            "<!ELEMENT item (name)><!ELEMENT name EMPTY>"
      xml = "<root><item><name/></item><item><name/><extra/></item></root>"
      error = assert_raise(REXML::Validation::ValidationException) do
        validate(dtd, xml)
      end
      assert_include(error.message, "/root/item[2]")
      assert_include(error.message, "<extra>")
      assert_include(error.message, "end of element")
    end

    def test_error_reports_unexpected_end_of_element
      dtd = "<!ELEMENT root (item+)>" \
            "<!ELEMENT item (name)><!ELEMENT name EMPTY>"
      error = assert_raise(REXML::Validation::ValidationException) do
        validate(dtd, "<root><item><name/></item><item/></root>")
      end
      assert_include(error.message, "/root/item[2]")
      assert_include(error.message, "unexpected end of <item>")
      assert_include(error.message, "<name>")
    end

    def test_error_reports_unexpected_text
      dtd = "<!ELEMENT a (b)><!ELEMENT b EMPTY>"
      error = assert_raise(REXML::Validation::ValidationException) do
        validate(dtd, "<a>oops<b/></a>")
      end
      assert_include(error.message, "/a")
      assert_include(error.message, 'unexpected text "oops"')
      assert_include(error.message, "<b>")
    end

    def test_undeclared_element
      error = assert_raise(REXML::Validation::ValidationException) do
        validate("<!ELEMENT a EMPTY>", "<b/>")
      end
      assert_include(error.message, "not declared")
      assert_include(error.message, "<b>")
    end

    def test_namespaced_names_match_qualified_dtd_names
      dtd = "<!ELEMENT x:a EMPTY>"
      assert_valid(dtd, "<x:a xmlns:x='urn:x'/>")
    end

    def test_invalid_content_model
      assert_raise(REXML::Validation::ValidationException) do
        REXML::Validation::DTDValidator.new("<!ELEMENT a (b|c,d)>")
      end
    end

    def test_validate_element_directly
      validator = REXML::Validation::DTDValidator.new(
        "<!ELEMENT a (b)><!ELEMENT b EMPTY>")
      document = REXML::Document.new("<a><b/></a>")
      assert_true(validator.validate(document.root))
    end

    def test_document_internal_subset
      xml = <<~XML
        <?xml version="1.0"?>
        <!DOCTYPE a [
          <!ELEMENT a (b)>
          <!ELEMENT b EMPTY>
        ]>
        <a><b/></a>
      XML
      document = REXML::Document.new(xml)
      validator = REXML::Validation::DTDValidator.new(document)
      assert_true(validator.validate(document))
    end

    def test_document_internal_subset_invalid
      xml = <<~XML
        <!DOCTYPE a [
          <!ELEMENT a (b)>
          <!ELEMENT b EMPTY>
        ]>
        <a><b/><b/></a>
      XML
      document = REXML::Document.new(xml)
      validator = REXML::Validation::DTDValidator.new(document)
      assert_raise(REXML::Validation::ValidationException) do
        validator.validate(document)
      end
    end

    def test_root_must_match_doctype_name
      xml = <<~XML
        <!DOCTYPE a [
          <!ELEMENT a EMPTY>
          <!ELEMENT b EMPTY>
        ]>
        <b/>
      XML
      document = REXML::Document.new(xml)
      validator = REXML::Validation::DTDValidator.new(document)
      error = assert_raise(REXML::Validation::ValidationException) do
        validator.validate(document)
      end
      assert_include(error.message, "DOCTYPE")
    end

    def test_document_without_dtd
      document = REXML::Document.new("<a/>")
      assert_raise(ArgumentError) do
        REXML::Validation::DTDValidator.new(document)
      end
    end

    def test_external_dtd_is_never_fetched
      xml = <<~XML
        <!DOCTYPE a SYSTEM "file:///nonexistent-dtd-validator-test.dtd" [
          <!ELEMENT a EMPTY>
        ]>
        <a/>
      XML
      document = REXML::Document.new(xml)
      validator = REXML::Validation::DTDValidator.new(document)
      assert_true(validator.validate(document))
    end

    def test_external_dtd_only_means_no_declarations
      xml = '<!DOCTYPE a SYSTEM "nonexistent-dtd-validator-test.dtd"><a/>'
      document = REXML::Document.new(xml)
      validator = REXML::Validation::DTDValidator.new(document)
      error = assert_raise(REXML::Validation::ValidationException) do
        validator.validate(document)
      end
      assert_include(error.message, "not declared")
    end

    def test_doctype_object_as_source
      xml = <<~XML
        <!DOCTYPE a [
          <!ELEMENT a EMPTY>
        ]>
        <a/>
      XML
      document = REXML::Document.new(xml)
      validator = REXML::Validation::DTDValidator.new(document.doctype)
      assert_true(validator.validate(document))
    end

    def test_deeply_nested_document
      dtd = "<!ELEMENT library (book+)>" \
            "<!ELEMENT book (title,author+)>" \
            "<!ELEMENT title (#PCDATA)>" \
            "<!ELEMENT author (#PCDATA)>"
      xml = "<library>" \
            "<book><title>A</title><author>B</author></book>" \
            "<book><title>C</title><author>D</author><author>E</author></book>" \
            "</library>"
      assert_valid(dtd, xml)
      bad = "<library>" \
            "<book><title>A</title><author>B</author></book>" \
            "<book><author>D</author><title>C</title></book>" \
            "</library>"
      error = assert_raise(REXML::Validation::ValidationException) do
        validate(dtd, bad)
      end
      assert_include(error.message, "/library/book[2]")
      assert_include(error.message, "<author>")
      assert_include(error.message, "<title>")
    end
  end
end
