# frozen_string_literal: false

require "test-unit"
require "rexml/document"
require "rexml/validation/dtd"

module REXMLTests
  class TestValidationDTD < Test::Unit::TestCase
    include REXML

    def validate(internal_subset, body, dtd = nil)
      document = REXML::Document.new(
        "<!DOCTYPE root [#{internal_subset}]>#{body}")
      REXML::Validation::DTD.new(document, dtd).validate
      document
    end

    def validate_error(internal_subset, body, dtd = nil)
      validate(internal_subset, body, dtd)
      flunk("expected REXML::Validation::ValidationException")
    rescue REXML::Validation::ValidationException => error
      error.message
    end

    def assert_valid(internal_subset, body, dtd = nil)
      assert_nothing_raised do
        validate(internal_subset, body, dtd)
      end
    end

    def assert_invalid(internal_subset, body, dtd = nil)
      message = validate_error(internal_subset, body, dtd)
      yield(message) if block_given?
      message
    end

    def test_empty_valid
      assert_valid("<!ELEMENT root EMPTY>", "<root/>")
      assert_valid("<!ELEMENT root EMPTY>",
                   "<root><!-- comment --><?pi data?></root>")
    end

    def test_empty_with_element
      message = assert_invalid(
        "<!ELEMENT root EMPTY><!ELEMENT child EMPTY>",
        "<root><child/></root>")
      assert_match(%r{unexpected element <child>}, message)
      assert_match(%r{at /root/child}, message)
      assert_match(/acceptable successors: \(end of content\)/,
                   message)
    end

    def test_empty_with_text
      message = assert_invalid(
        "<!ELEMENT root EMPTY>",
        "<root> text </root>")
      assert_match(/declared EMPTY/, message)
      assert_match(/text " text "/, message)
      assert_match(%r{at /root}, message)
    end

    def test_any_accepts_text_elements_comments_and_pis
      assert_valid(
        "<!ELEMENT root ANY><!ELEMENT child EMPTY>",
        "<root>some text<!-- c --><?pi data?><child/></root>")
    end

    def test_any_still_requires_declared_children
      message = assert_invalid(
        "<!ELEMENT root ANY>",
        "<root><child/></root>")
      assert_match(/<child> is not declared/, message)
      assert_match(%r{at /root/child}, message)
    end

    def test_mixed_text_only
      assert_valid("<!ELEMENT root (#PCDATA)>",
                   "<root>hello world</root>")
    end

    def test_mixed_text_and_allowed_children
      subset = mixed_subset("a", "b")
      assert_valid(subset, "<root>x<a/>y<b/>z</root>")
      assert_valid(subset, "<root><b/><a/></root>")
    end

    def test_mixed_disallowed_child
      subset = mixed_subset("a") +
               "<!ELEMENT b EMPTY>"
      message = assert_invalid(subset, "<root>x<a/><b/></root>")
      assert_match(/element <b> is not allowed/, message)
      assert_match(/is not allowed in the mixed/, message)
      assert_match(%r{at /root/b}, message)
      assert_match(/acceptable elements: <a>/, message)
    end

    def test_sequence
      subset = elements_subset("root", "(a,b,c)")
      assert_valid(subset, "<root><a/><b/><c/></root>")

      message = assert_invalid(subset, "<root><a/><c/><b/></root>")
      assert_match(/unexpected element <c>/, message)
      assert_match(/acceptable successors: <b>/, message)
      assert_match(%r{at /root/c}, message)
    end

    def test_sequence_incomplete
      subset = elements_subset("root", "(a,b)")
      message = assert_invalid(subset, "<root><a/></root>")
      assert_match(/content of <root> at \/root ended/, message)
      assert_match(/acceptable successors: <b>/, message)
    end

    def test_choice
      subset = elements_subset("root", "(a|b)")
      assert_valid(subset, "<root><a/></root>")
      assert_valid(subset, "<root><b/></root>")

      message = assert_invalid(
        subset + "<!ELEMENT c EMPTY>",
        "<root><c/></root>")
      assert_match(/unexpected element <c>/, message)
      assert_match(/acceptable successors: <a>, <b>/, message)
    end

    def test_occurrence_indicators
      subset = elements_subset("root", "(a?,b*,c+)")
      assert_valid(subset, "<root><c/></root>")
      assert_valid(subset, "<root><a/><b/><b/><c/><c/></root>")

      message = assert_invalid(subset, "<root><a/><a/></root>")
      assert_match(/unexpected element <a>/, message)
      assert_match(/acceptable successors: <b>, <c>/, message)

      message = assert_invalid(subset, "<root><b/></root>")
      assert_match(/ended before its content model/, message)
      assert_match(/acceptable successors: <b>, <c>/, message)
    end

    def test_nested_groups_and_repeated_sequence
      subset = elements_subset("root", "((a,b)+|c)")
      assert_valid(subset, "<root><a/><b/></root>")
      assert_valid(subset, "<root><a/><b/><a/><b/></root>")
      assert_valid(subset, "<root><c/></root>")

      message = assert_invalid(subset, "<root><a/></root>")
      assert_match(/acceptable successors: <b>/, message)
    end

    def test_comments_and_processing_instructions_are_ignored
      subset = elements_subset("root", "(a,b)")
      assert_valid(
        subset,
        "<root><!-- lead --><a/><?app run?>" +        "<!-- mid --><b/><?tail done?></root>")
    end

    def test_whitespace_text_is_ignored_in_element_content
      subset = elements_subset("root", "(a,b)")
      assert_valid(subset,
                   "<root>\n  <a/>\n  <b/>\n</root>")
    end

    def test_non_whitespace_text_in_element_content
      subset = elements_subset("root", "(a,b)")
      message = assert_invalid(subset, "<root><a/>bad<b/></root>")
      assert_match(/element-only content model/, message)
      assert_match(/text "bad"/, message)
      assert_match(/acceptable successors: <b>/, message)
    end

    def test_cdata_is_non_whitespace_text
      subset = elements_subset("root", "(a)")
      message = assert_invalid(subset,
                               "<root><![CDATA[data]]></root>")
      assert_match(/CDATA "data"/, message)
    end

    def test_error_path_uses_sibling_position
      subset = elements_subset("root", "(a,a,b)")
      message = assert_invalid(subset,
                               "<root><a/><a/><a/></root>")
      assert_match(%r{at /root/a\[3\]}, message)
    end

    def test_nested_element_path
      subset = elements_subset("root", "(a)") +
               "<!ELEMENT a (b)><!ELEMENT c EMPTY>"
      message = assert_invalid(subset, "<root><a><c/></a></root>")
      assert_match(/unexpected element <c>/, message)
      assert_match(%r{at /root/a/c}, message)
    end

    def test_undeclared_element
      message = validate_error(
        elements_subset("root", "(a)"),
        "<root><a><b/></a></root>")
      assert_match(/<b> is not declared/, message)
      assert_match(%r{at /root/a/b}, message)
    end

    def test_root_name_must_match_doctype
      document = REXML::Document.new(
        "<!DOCTYPE expected [<!ELEMENT expected EMPTY>]>" +        "<actual/>")
      message = assert_raise(
        REXML::Validation::ValidationException) do
        REXML::Validation::DTD.validate(document)
      end.message
      assert_match(/DTD root element must be <expected>/, message)
      assert_match(/got <actual>/, message)
    end

    def test_caller_provided_external_subset_string
      external = elements_subset("root", "(a,b)")
      document = REXML::Document.new(
        "<!DOCTYPE root SYSTEM \"root.dtd\"><root><a/><b/>" +        "</root>")
      assert_nothing_raised do
        REXML::Validation::DTD.validate(document, external)
      end

      assert_raise(REXML::Validation::ValidationException) do
        REXML::Validation::DTD.validate(
          REXML::Document.new(
            "<!DOCTYPE root SYSTEM \"root.dtd\">" +            "<root><b/><a/></root>"),
          external)
      end
    end

    def test_external_subset_is_not_fetched
      document = REXML::Document.new(
        "<!DOCTYPE root SYSTEM \"file:///nonexistent.dtd\">" +        "<root/>")
      assert_nothing_raised do
        REXML::Validation::DTD.validate(document)
      end
    end

    def test_internal_subset_takes_precedence
      external = elements_subset("root", "(a)")
      document = REXML::Document.new(
        "<!DOCTYPE root [<!ELEMENT root EMPTY>]><root/>")
      assert_nothing_raised do
        REXML::Validation::DTD.validate(document, external)
      end
    end

    def test_validate_element_subtree_with_provided_dtd
      dtd = elements_subset("root", "(a,b)")
      element = REXML::Document.new("<root><a/><b/></root>").root
      assert_nothing_raised do
        REXML::Validation::DTD.validate(element, dtd)
      end

      element = REXML::Document.new("<root><b/></root>").root
      message = assert_raise(
        REXML::Validation::ValidationException) do
        REXML::Validation::DTD.validate(element, dtd)
      end.message
      assert_match(/acceptable successors: <a>/, message)
    end

    def test_doctype_object_is_accepted_as_dtd_source
      document = REXML::Document.new(<<-XML)
<!DOCTYPE root [
  <!ELEMENT root (a)>
  <!ELEMENT a EMPTY>
]>
<root><a/></root>
      XML
      assert_nothing_raised do
        REXML::Validation::DTD.new(
          document.root, document.doctype).validate
      end
    end

    def test_malformed_content_model_raises
      error = assert_raise(
        REXML::Validation::DTD::ContentModel::ParseError) do
        REXML::Validation::DTD::ContentModel.parse("(a,b)#")
      end
      assert_kind_of(REXML::Validation::ValidationException, error)
    end

    def test_no_declarations_skips_content_validation
      document = REXML::Document.new("<root><child>x</child></root>")
      assert_nothing_raised do
        REXML::Validation::DTD.validate(document)
      end
    end

    private

    def elements_subset(name, model)
      declarations = ["<!ELEMENT #{name} #{model}>"]
      model.scan(/[a-z]\w*/).uniq.each do |child|
        declarations << "<!ELEMENT #{child} EMPTY>"
      end
      declarations.join
    end

    def mixed_subset(*names)
      choices = (["#PCDATA"] + names).join("|")
      declarations = ["<!ELEMENT root (#{choices})*>"]
      names.each { |name| declarations << "<!ELEMENT #{name} EMPTY>" }
      declarations.join
    end
  end
end
