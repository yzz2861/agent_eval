# frozen_string_literal: true

require 'test_helper'

class LoopLabelTest < Minitest::Test
  include Liquid

  def test_unlabeled_break_and_continue_still_target_innermost_loop
    assert_template_result('1', '{% for i in (1..3) %}{% if i == 2 %}{% break %}{% endif %}{{ i }}{% endfor %}')
    assert_template_result('13', '{% for i in (1..3) %}{% if i == 2 %}{% continue %}{% endif %}{{ i }}{% endfor %}')
    # unlabeled break inside nested loops only exits the inner one
    assert_template_result(
      '1:12:13:1',
      '{% for i in (1..3) %}{% for j in (1..3) %}{% if j == 2 %}{% break %}{% endif %}{{ i }}:{{ j }}{% endfor %}{% endfor %}',
    )
  end

  def test_labeled_break_exits_the_targeted_outer_loop
    assert_template_result(
      '1-1;',
      '{% for i in (1..3) label: outer %}' \
        '{% for j in (1..3) %}{% if j == 2 %}{% break outer %}{% endif %}{{ i }}-{{ j }};{% endfor %}' \
        'never{% endfor %}',
    )
  end

  def test_labeled_continue_skips_to_next_iteration_of_outer_loop
    assert_template_result(
      '1:112:213:31',
      '{% for i in (1..3) label: outer %}{{ forloop.index }}:{{ i }}' \
        '{% for j in (1..3) %}{% if j == 2 %}{% continue outer %}{% endif %}{{ j }}{% endfor %}' \
        'skipped;{% endfor %}',
    )
  end

  def test_labeled_control_flow_with_same_variable_name_in_both_loops
    # inner `item` shadows the outer one; continuing the outer loop must
    # fully unwind the inner scope so the outer `item` is restored
    assert_template_result(
      'A1:B7B8A2:B7B8A3:B7B8',
      '{% for item in (1..3) label: outer %}A{{ item }}:' \
        '{% for item in (7..9) %}B{{ item }}{% if item == 8 %}{% continue outer %}{% endif %}{% endfor %}' \
        'C{{ item }};{% endfor %}',
    )
  end

  def test_inner_context_is_fully_unwound_when_continuing_outer_loop
    # three nesting levels, continue targets the middle loop: the innermost
    # scope must be unwound and the middle loop variable must stay intact
    assert_template_result(
      '[1-3-456+4][2-3-456+4]',
      '{% for i in (1..2) label: outer %}[{{ i }}' \
        '{% for j in (3..4) label: middle %}-{{ j }}' \
        '{% for k in (5..6) %}{% if k == 5 and j == 3 %}{% continue middle %}{% endif %}{{ k }}{% endfor %}' \
        '+{{ j }}{% endfor %}]{% endfor %}',
    )
  end

  def test_labeled_break_inside_conditional_branch
    assert_template_result(
      'a1b1b2a2b1b2',
      '{% for i in (1..5) label: outer %}{% if i > 2 %}{% break outer %}{% else %}a{{ i }}{% endif %}' \
        '{% for j in (1..2) %}b{{ j }}{% endfor %}{% endfor %}',
    )
  end

  def test_labeled_loop_with_else_branch
    # else renders when the collection is empty, label does not change that
    assert_template_result(
      'empty',
      '{% for x in items label: outer %}{{ x }}{% else %}empty{% endfor %}',
      { 'items' => [] },
    )
    # break targeting the outer loop from the inner loop's else branch
    assert_template_result(
      '1',
      '{% for x in (1..3) label: outer %}{{ x }}' \
        '{% for y in items %}{{ y }}{% else %}{% break outer %}{% endfor %}{% endfor %}',
      { 'items' => [] },
    )
  end

  def test_forloop_state_stays_correct_when_inner_loops_unwind
    assert_template_result(
      '[1:12[2:12[3:12',
      '{% for i in (1..3) label: outer %}[{{ forloop.index }}:' \
        '{% for j in (1..5) %}{% if j == 3 %}{% continue outer %}{% endif %}{{ j }}{% endfor %}]' \
        '{% endfor %}',
    )
  end

  def test_offset_continue_state_stays_correct_after_labeled_break
    # the first loop is left via a labeled break from the inner loop;
    # the offset of the shared loop name must already point past its segment
    assert_template_result(
      '|456',
      '{% for i in (1..10) label: outer limit: 3 offset: continue %}' \
        '{% for j in (1..2) %}{% break outer %}{% endfor %}{{ i }}{% endfor %}' \
        '|{% for i in (1..10) limit: 3 offset: continue %}{{ i }}{% endfor %}',
    )
  end

  def test_sibling_loops_may_reuse_the_same_label
    assert_template_result(
      '1234',
      '{% for i in (1..2) label: same %}{{ i }}{% endfor %}' \
        '{% for i in (3..4) label: same %}{{ i }}{% endfor %}',
    )
  end

  def test_labeled_break_crossing_tablerow_unwinds_it
    assert_template_result(
      %(<table><tr class="row1">\n<td class="col1">1</td><td class="col2"></td></tr>\n</table>),
      '<table>{% for i in (1..3) label: outer %}{% tablerow j in (1..3) %}' \
        '{% if j == 2 %}{% break outer %}{% endif %}{{ j }}{% endtablerow %}{% endfor %}</table>',
    )
  end

  def test_break_with_unknown_label_is_a_syntax_error
    assert_match_syntax_error(
      /No enclosing loop declared label 'nowhere'/,
      '{% for i in (1..3) %}{% break nowhere %}{% endfor %}',
    )
    assert_match_syntax_error(
      /No enclosing loop declared label 'nowhere'/,
      '{% continue nowhere %}',
    )
  end

  def test_nested_loop_cannot_redeclare_visible_label
    assert_match_syntax_error(
      /Loop label 'a' is already declared in an enclosing loop/,
      '{% for i in (1..3) label: a %}{% for j in (1..3) label: a %}{% endfor %}{% endfor %}',
    )
  end

  def test_for_loop_cannot_declare_label_twice
    assert_match_syntax_error(
      /Loop label declared more than once/,
      '{% for i in (1..3) label: a label: b %}{% endfor %}',
    )
  end

  def test_invalid_label_syntax_is_a_syntax_error
    assert_match_syntax_error(
      /Invalid loop label/,
      '{% for i in (1..3) label: a %}{% break a b %}{% endfor %}',
    )
  end

  def test_label_is_not_visible_outside_its_loop
    assert_match_syntax_error(
      /No enclosing loop declared label 'a'/,
      '{% for i in (1..3) label: a %}{% endfor %}{% break a %}',
    )
  end

  def test_label_is_visible_in_else_branch_of_its_own_loop
    assert_template_result(
      'else',
      '{% for i in items label: a %}{{ i }}{% else %}else{% break a %}{% endfor %}',
      { 'items' => [] },
    )
  end

  def test_labeled_break_cannot_cross_render_boundary
    exception = assert_raises(Liquid::SyntaxError) do
      assert_template_result(
        '',
        '{% for i in (1..3) label: outer %}{% render "snippet" %}{% endfor %}',
        partials: { 'snippet' => '{% break outer %}' },
      )
    end
    assert_match(/No enclosing loop declared label 'outer'/, exception.message)
  end

  def test_labeled_continue_cannot_cross_render_boundary
    exception = assert_raises(Liquid::SyntaxError) do
      assert_template_result(
        '',
        '{% for i in (1..3) label: outer %}{% render "snippet" %}{% endfor %}',
        partials: { 'snippet' => '{% continue outer %}' },
      )
    end
    assert_match(/No enclosing loop declared label 'outer'/, exception.message)
  end

  def test_partial_may_declare_its_own_independent_label
    assert_template_result(
      '11',
      '{% for i in (1..2) label: outer %}{% render "snippet" %}{% endfor %}',
      partials: { 'snippet' => '{% for i in (1..3) label: outer %}{% if i == 2 %}{% break outer %}{% endif %}' \
        '{{ i }}{% endfor %}' },
    )
  end
end
