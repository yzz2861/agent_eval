require 'helper'

class TestSlimTagOmission < TestSlim
  def assert_omit(expected, source, options = {})
    assert_html(expected, source, { omit_end_tags: true, format: :html }.merge(options))
  end

  def test_disabled_by_default
    source = %q{
ul
  li a
  li b
}
    assert_html '<ul><li>a</li><li>b</li></ul>', source, format: :html
  end

  def test_list_items
    source = %q{
ul
  li a
  li b
}
    assert_omit '<ul><li>a<li>b</ul>', source
  end

  def test_list_item_attributes
    source = %q{
ul
  li.a x=1 a
  li#b b
}
    assert_omit '<ul><li class="a" x="1">a<li id="b">b</ul>', source
  end

  def test_list_item_followed_by_output
    source = %q{
ul
  li a
  = dyn
}
    assert_omit '<ul><li>a</li>1</ul>', source, locals: { dyn: 1 }
  end

  def test_list_item_followed_by_control_code
    source = %q{
ul
  li a
  - if true
    li b
}
    assert_omit '<ul><li>a</li><li>b</li></ul>', source
  end

  def test_list_item_in_control_code
    source = %q{
ul
  - if true
    li a
  li b
}
    # The li inside the if block keeps its end tag because the
    # following output is not known at compile time
    assert_omit '<ul><li>a</li><li>b</ul>', source
  end

  def test_list_item_in_loop
    source = %q{
ul
  - 2.times do |i|
    li = i
}
    assert_omit '<ul><li>0</li><li>1</li></ul>', source
  end

  def test_list_item_followed_by_comment
    source = %q{
ul
  li a
  /! comment
  li b
}
    assert_omit '<ul><li>a</li><!--comment--><li>b</ul>', source
  end

  def test_list_item_followed_by_text
    source = %q{
ul
  li a
  | text
  li b
}
    assert_omit '<ul><li>a</li>text<li>b</ul>', source
  end

  def test_list_item_followed_by_raw_output
    source = %q{
ul
  li a
  == html
}
    assert_omit '<ul><li>a</li><b>x</b></ul>', source, locals: { html: '<b>x</b>' }
  end

  def test_definition_list
    source = %q{
dl
  dt term
  dd def
  dt term2
  dd def2
}
    assert_omit '<dl><dt>term<dd>def<dt>term2<dd>def2</dl>', source
  end

  def test_table
    source = %q{
table
  thead
    tr
      th h1
      th h2
  tbody
    tr
      td a
      td b
    tr
      td c
      td d
}
    assert_omit '<table><thead><tr><th>h1<th>h2<tbody><tr><td>a<td>b<tr><td>c<td>d</table>', source
  end

  def test_paragraphs
    source = %q{
p one
p two
div
  p three
}
    assert_omit '<p>one<p>two<div><p>three</div>', source
  end

  def test_paragraph_followed_by_inline_element
    source = %q{
p one
span two
}
    assert_omit '<p>one</p><span>two</span>', source
  end

  def test_paragraph_in_link
    source = %q{
a
  p text
}
    # The p end tag may not be omitted inside an a element
    assert_omit '<a><p>text</p></a>', source
  end

  def test_paragraph_in_custom_element
    source = %q{
my-el
  p text
}
    assert_omit '<my-el><p>text</p></my-el>', source
  end

  def test_options
    source = %q{
select
  option a
  option b
  optgroup
    option c
}
    assert_omit '<select><option>a<option>b<optgroup><option>c</select>', source
  end

  def test_head_body
    source = %q{
html
  head
    title t
  body
    p x
}
    assert_omit '<html><head><title>t</title><body><p>x</html>', source
  end

  def test_foreign_content_svg
    source = %q{
svg
  p a
  p b
}
    # End tag omission rules do not apply inside SVG
    assert_omit '<svg><p>a</p><p>b</p></svg>', source
  end

  def test_foreign_content_math
    source = %q{
math
  p a
  p b
}
    assert_omit '<math><p>a</p><p>b</p></math>', source
  end

  def test_xhtml_format_untouched
    source = %q{
ul
  li a
  li b
}
    assert_html '<ul><li>a</li><li>b</li></ul>', source, omit_end_tags: true, format: :xhtml
  end

  def test_pretty_untouched
    source = %q{
ul
  li a
  li b
}
    assert_omit "<ul>\n  <li>\n    a\n  </li>\n  <li>\n    b\n  </li>\n</ul>", source, pretty: true
  end

  def test_nested_lists
    source = %q{
ul
  li
    ul
      li a
      li b
  li c
}
    assert_omit '<ul><li><ul><li>a<li>b</ul><li>c</ul>', source
  end

  def test_empty_list_item
    source = %q{
ul
  li
  li b
}
    assert_omit '<ul><li><li>b</ul>', source
  end
end
