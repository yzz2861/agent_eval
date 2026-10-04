# coding: binary
# frozen_string_literal: false

require_relative '../helper'
require "rexml/c14n/exclusive"

module REXMLTests
  class ExclusiveC14NTest < Test::Unit::TestCase
    def canonicalize(xml, with_comments: false, prefixes: nil, xpath: nil)
      document = REXML::Document.new(xml)
      node = xpath ? REXML::XPath.first(document, xpath) : document
      REXML::C14N::Exclusive.new(with_comments, prefixes).canonicalize(node)
    end

    def binary(string)
      string.b
    end

    class PublicVectorTest < self
      # Example from the Exclusive XML Canonicalization specification,
      # "InclusiveNamespaces PrefixList" section.
      def test_inclusive_namespaces_prefix_list_vector
        xml =
          '<n0:local xmlns:n0="http://idealliance.org/DataModel2.0/" ' \
          'xmlns="http://www.w3.org/TR/REC-html40">' \
          '<n0:genericValue genericValue43="line1&#xA;line2&#x9;tab" ' \
          'n0:genericValue38="Weekly" n0:genericValue39="20030624" ' \
          'n0:genericValue40="June 24, 2003" n0:genericValue59="1">' \
          '</n0:genericValue></n0:local>'
        expected =
          '<n0:local xmlns:n0="http://idealliance.org/DataModel2.0/">' \
          '<n0:genericValue genericValue43="line1&#xA;line2&#x9;tab" ' \
          'n0:genericValue38="Weekly" n0:genericValue39="20030624" ' \
          'n0:genericValue40="June 24, 2003" n0:genericValue59="1">' \
          '</n0:genericValue></n0:local>'
        assert_equal(binary(expected),
                     canonicalize(xml, prefixes: ["n0"]))
      end

      def test_inclusive_namespaces_prefix_list_forces_inherited_prefix
        xml = '<foo:root xmlns:foo="http://example.com/foo">' \
              '<bar xmlns="http://example.com/bar">' \
              '<x foo:attr="1"/></bar></foo:root>'
        expected =
          '<x xmlns="http://example.com/bar" ' \
          'xmlns:foo="http://example.com/foo" foo:attr="1"></x>'
        assert_equal(binary(expected),
                     canonicalize(xml,
                                  prefixes: ["foo"],
                                  xpath: "/foo:root/bar/x"))
      end

      def test_default_namespace_is_emitted_only_when_used
        xml = '<doc xmlns="http://example.org/ns">' \
              '<x:a xmlns:x="http://example.org/x" attr="v&amp;w">' \
              'text&lt;</x:a><b/></doc>'
        expected =
          '<doc xmlns="http://example.org/ns">' \
          '<x:a xmlns:x="http://example.org/x" attr="v&amp;w">' \
          'text&lt;</x:a><b></b></doc>'
        assert_equal(binary(expected), canonicalize(xml))
      end

      def test_default_namespace_is_cleared
        xml = '<a xmlns="http://example.org/a">' \
              '<b xmlns=""><c>x</c></b></a>'
        expected =
          '<a xmlns="http://example.org/a"><b xmlns=""><c>x</c></b></a>'
        assert_equal(binary(expected), canonicalize(xml))
      end

      def test_attributes_are_sorted_by_namespace_uri_then_local_name
        xml = '<doc xmlns:a="http://example.org/a" ' \
              'xmlns:b="http://example.org/b">' \
              '<e a:z="1" b:y="2" x="3" a:a="4"/></doc>'
        expected =
          '<doc><e xmlns:a="http://example.org/a" ' \
          'xmlns:b="http://example.org/b" x="3" a:a="4" a:z="1" ' \
          'b:y="2"></e></doc>'
        assert_equal(binary(expected), canonicalize(xml))
      end

      def test_namespace_prefix_is_redeclared_when_rebound
        xml = '<r xmlns:p="http://example.org/1">' \
              '<a xmlns:p="http://example.org/2"><p:x/></a>' \
              '<p:y/></r>'
        expected =
          '<r><a><p:x xmlns:p="http://example.org/2"></p:x></a>' \
          '<p:y xmlns:p="http://example.org/1"></p:y></r>'
        assert_equal(binary(expected), canonicalize(xml))
      end

      def test_cdata_is_rendered_as_text_with_canonical_escapes
        xml = '<doc><![CDATA[a < b & c]]>after</doc>'
        expected = '<doc>a &lt; b &amp; cafter</doc>'
        assert_equal(binary(expected), canonicalize(xml))
      end

      def test_text_and_attribute_escapes
        xml = '<r a="1&quot;2&lt;3&amp;4">t&gt;y&amp;z</r>'
        expected = '<r a="1&quot;2&lt;3&amp;4">t&gt;y&amp;z</r>'
        assert_equal(binary(expected), canonicalize(xml))
      end

      def test_character_reference_for_tab_in_attribute_is_escaped
        xml = '<r a="x&#x9;y"/>'
        assert_equal(binary('<r a="x&#x9;y"></r>'), canonicalize(xml))
      end

      def test_xml_prefix_is_never_declared
        xml = '<r xml:lang="en" xmlns:x="http://example.org/x">' \
              '<x:a/></r>'
        expected =
          '<r xml:lang="en"><x:a xmlns:x="http://example.org/x">' \
          '</x:a></r>'
        assert_equal(binary(expected), canonicalize(xml))
      end

      def test_empty_elements_use_open_and_close_tags
        assert_equal(binary('<r><a></a><b></b></r>'),
                     canonicalize('<r><a/><b></b></r>'))
      end

      def test_document_level_processing_instruction_and_comment
        xml = '<?app v?><!-- keep --><r/><?tail ok?>'
        assert_equal(binary("<?app v?>\n<r></r>\n<?tail ok?>"),
                     canonicalize(xml))
        output = canonicalize(xml, with_comments: true)
        assert_equal(binary("<?app v?>\n<!-- keep -->\n<r></r>\n<?tail ok?>"),
                     output)
        assert_include(output, '<!-- keep -->')
        assert_include(output, "<?app v?>\n")
      end

      def test_comments_are_omitted_by_default
        xml = '<r><!-- one --><a><!-- two --></a></r>'
        assert_equal(binary('<r><a></a></r>'), canonicalize(xml))
      end

      def test_comments_are_kept_when_requested
        xml = '<r><!-- one --><a><!-- two --></a></r>'
        expected = '<r><!-- one --><a><!-- two --></a></r>'
        assert_equal(binary(expected),
                     canonicalize(xml, with_comments: true))
      end

      def test_comment_whitespace_is_normalized
        xml = "<r><!-- x\ty\nz --></r>"
        assert_equal(binary('<r><!-- x y z --></r>'),
                     canonicalize(xml, with_comments: true))
      end

      def test_output_is_utf8_binary_string
        xml = "<r xmlns=\"http://example.org/\">\u{4e2d}\u{6587}</r>"
        output = canonicalize(xml)
        assert_equal(::Encoding::UTF_8, output.encoding)
        assert_equal("<r xmlns=\"http://example.org/\">\u{4e2d}\u{6587}</r>",
                     output)
      end
    end

    class EmbeddedSubtreeTest < self
      def test_inherited_namespace_is_rendered_on_subtree_root
        xml = '<n0:doc xmlns:n0="http://example.org/fake">' \
              '<n1:elem xmlns:n1="http://example.org/fake1" attr="out">' \
              '<n0:child>content</n0:child></n1:elem></n0:doc>'
        expected =
          '<n0:child xmlns:n0="http://example.org/fake">content</n0:child>'
        assert_equal(binary(expected),
                     canonicalize(xml, xpath: '/n0:doc/n1:elem/n0:child'))
      end

      def test_inherited_namespace_used_by_attribute_is_rendered
        xml = '<r xmlns:n="http://example.org/n"><a>' \
              '<b n:attr="v"/></a></r>'
        expected =
          '<b xmlns:n="http://example.org/n" n:attr="v"></b>'
        assert_equal(binary(expected),
                     canonicalize(xml, xpath: '/r/a/b'))
      end

      def test_unused_inherited_namespace_is_not_rendered
        xml = '<r xmlns:u="http://example.org/u"><a><b>x</b></a></r>'
        assert_equal(binary('<b>x</b>'),
                     canonicalize(xml, xpath: '/r/a/b'))
      end

      def test_default_namespace_cleared_in_embedded_subtree
        xml = '<r xmlns="http://example.org/d"><a>' \
              '<b xmlns=""><c>t</c></b></a></r>'
        expected = '<b><c>t</c></b>'
        assert_equal(binary(expected),
                     canonicalize(xml, xpath: '/r/a/b'))
      end

      def test_default_namespace_inherited_and_used_by_subtree
        xml = '<r xmlns="http://example.org/d"><a><b><c/></b></a></r>'
        expected =
          '<b xmlns="http://example.org/d"><c></c></b>'
        assert_equal(binary(expected),
                     canonicalize(xml, xpath: '/r/a/b'))
      end

      def test_default_prefix_list_carries_default_namespace
        xml = '<r xmlns="http://example.org/d"><a><b><c/></b></a></r>'
        expected =
          '<b xmlns="http://example.org/d"><c></c></b>'
        assert_equal(binary(expected),
                     canonicalize(xml,
                                  prefixes: ["#default"],
                                  xpath: '/r/a/b'))
      end

      def test_inclusive_prefix_used_only_in_sibling
        xml = '<r xmlns:p="http://example.org/p">' \
              '<a><b foo="1"/></a><p:x/></r>'
        # The PrefixList forces rendering of p in scope at the subtree root.
        assert_equal(binary('<b xmlns:p="http://example.org/p" foo="1"></b>'),
                     canonicalize(xml,
                                  prefixes: ["p"],
                                  xpath: '/r/a/b'))
      end

      def test_comments_inside_embedded_subtree
        xml = '<r xmlns="http://example.org/d"><a>' \
              '<!-- note --><b>x</b></a></r>'
        assert_equal(binary('<b xmlns="http://example.org/d">x</b>'),
                     canonicalize(xml, xpath: '/r/a/b'))
        assert_equal(binary('<!-- note -->'),
                     canonicalize(xml,
                                  with_comments: true,
                                  xpath: '/r/a/comment()'))
      end
    end

    class NonMutationTest < self
      def test_input_document_is_not_modified
        xml = '<a xmlns="http://example.org/a">' \
              '<b xmlns:foo="http://example.org/foo" foo:x="1">' \
              '<!-- c -->text&amp;x</b></a>'
        document = REXML::Document.new(xml)
        before = document.to_s
        REXML::C14N::Exclusive.new(false, ["foo"]).canonicalize(document)
        REXML::C14N::Exclusive.new(true, []).canonicalize(document.root)
        assert_equal(before, document.to_s)
      end

      def test_repeated_canonicalization_is_stable
        xml = '<r xmlns:p="http://example.org/p"><a>' \
              '<b xmlns:p="http://example.org/2"/></a></r>'
        document = REXML::Document.new(xml)
        first = REXML::C14N::Exclusive.new.canonicalize(document)
        second = REXML::C14N::Exclusive.new.canonicalize(document)
        assert_equal(first, second)
      end

      def test_deeply_nested_document_does_not_use_recursion
        depth = 5000
        xml = ('<a xmlns="http://example.org/d">' * depth) +
              ('</a>' * depth)
        document = REXML::Document.new(xml)
        output = REXML::C14N::Exclusive.new.canonicalize(document)
        prefix = '<a xmlns="http://example.org/d">'
        assert_equal(prefix, output[0, prefix.bytesize])
        assert_include(output, '</a></a>')
      end

      def test_inclusive_prefix_is_re_emitted_after_rebinding
        xml = '<r xmlns:p="http://example.org/1">' \
              '<a xmlns:p="http://example.org/2">' \
              '<b><c/></b></a></r>'
        expected =
          '<b xmlns:p="http://example.org/2"><c></c></b>'
        assert_equal(binary(expected),
                     canonicalize(xml,
                                  prefixes: ["p"],
                                  xpath: '/r/a/b'))
      end

      def test_canonicalize_element_directly
        element = REXML::Element.new('r')
        element.add_namespace('x', 'http://example.org/x')
        child = element.add_element('x:c')
        child.add_text('v')
        output = REXML::C14N::Exclusive.new.canonicalize(element)
        assert_equal(binary('<r><x:c xmlns:x="http://example.org/x">v</x:c></r>'),
                     output)
      end

      def test_output_target_is_supported_and_not_modified
        document = REXML::Document.new('<r>x</r>')
        target = +""
        result = REXML::C14N::Exclusive.new.canonicalize(document, target)
        assert_same(target, result)
        assert_equal(binary('<r>x</r>'), target.b)
      end
    end
  end
end
