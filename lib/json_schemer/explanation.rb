# frozen_string_literal: true
module JSONSchemer
  # Branch-tree explanation of combination keyword failures (`allOf`/`anyOf`/`oneOf`/`not`
  # and `if`/`then`/`else`). Unlike the standard output formats, identical leaf errors
  # shared by several branches are merged once (with the matching branch indexes), and
  # `oneOf` states whether every branch failed or several branches matched.
  module Explanation
    module_function

    BRANCH_KEYWORDS = {
      Draft202012::Vocab::Applicator::AllOf => 'allOf',
      Draft202012::Vocab::Applicator::AnyOf => 'anyOf',
      Draft202012::Vocab::Applicator::OneOf => 'oneOf'
    }.freeze

    def build(root_result, limit)
      root_result.valid ? root_result.to_output_unit : build_invalid(root_result, limit)
    end

    def build_invalid(result, limit, branch_index = nil)
      case result.source
      when Draft202012::Vocab::Applicator::Not
        build_not(result, limit)
      when *BRANCH_KEYWORDS.keys
        build_branches(result, limit)
      else
        unit = base_unit(result, false)
        unit['type'] = result.type || CLASSIC_ERROR_TYPES[result.source.class]
        unit['details'] = result.details if result.details
        attach_children(unit, result, limit, branch_index)
      end
    end

    def build_not(result, limit)
      unit = base_unit(result, false)
      unit['reason'] = 'not_schema_matched'
      unit['annotations'] = build_matched_schema(result.nested.first, limit)
      unit
    end

    # Flatten the successful subschema node: the explanation attaches directly
    # to the `not` keyword, so the extra subschema location would be misleading.
    def build_matched_schema(result, limit)
      matched = build_valid(result, limit)
      matched.fetch('annotations', [matched])
    end

    def build_branches(result, limit)
      keyword = BRANCH_KEYWORDS.fetch(result.source.class)
      nested = result.nested || []
      unit = base_unit(result, false)
      unit['keyword'] = keyword
      unit['branchCount'] = nested.size

      matched = nested.each_index.select { |index| nested.fetch(index).valid }
      unit['matchedBranchIndexes'] = matched unless matched.empty?

      unit['reason'] = case keyword
      when 'oneOf'
        matched.empty? ? 'all_branches_failed' : 'multiple_branches_matched'
      when 'allOf'
        'all_branches_required'
      else
        'all_branches_failed'
      end

      branch_units = nested.map.with_index do |branch_result, index|
        build_branch(branch_result, index, limit)
      end

      # Cap the branch tree first (keeping every matched `oneOf` branch), then
      # merge identical leaves within the retained branches so the reported
      # counts cannot contradict the shown branches.
      if limit
        matched_units = branch_units.select { |branch| branch.fetch('valid') }
        failed_units = branch_units.reject { |branch| branch.fetch('valid') }
        budget = limit <= matched_units.size ? 0 : limit - matched_units.size
        if matched_units.size + failed_units.size > limit
          kept_failed = failed_units.first(budget)
          unit['branchOmittedCount'] = failed_units.size - kept_failed.size
          branch_units = (matched_units + kept_failed).sort_by { |branch| branch.fetch('branchIndex') }
        end
      end

      merge_identical_leaves!(unit, branch_units)

      unit['errors'] = capped(unit.fetch('errors'), limit, unit, 'errorOmittedCount') { true } if unit['errors']
      unit['branches'] = branch_units

      unit
    end

    def build_branch(result, index, limit)
      unit = result.valid ? build_valid(result, limit) : build_invalid(result, limit, index)
      unit['branchIndex'] = index
      unit
    end

    # Merge identical leaf errors appearing in two or more (distinct) branches.
    # The merged leaves are attached to the combination node and removed from the
    # branch subtrees; the branch nodes themselves are always retained.
    def merge_identical_leaves!(unit, branch_units)
      leaves = []
      branch_units.each do |branch|
        collect_leaves(branch, [branch.fetch('branchIndex')], leaves)
      end

      grouped = leaves.group_by { |entry| leaf_key(entry.fetch(:leaf)) }
      grouped.each_value do |entries|
        branches = entries.map { |entry| entry.fetch(:branches) }.flatten.uniq.sort
        next unless branches.size > 1
        merged = entries.first.fetch(:leaf).dup
        merged['occurrenceCount'] = entries.size
        merged['branchIndexes'] = branches
        locations = entries.map { |entry| entry.fetch(:leaf).fetch('keywordLocation') }.uniq.sort
        merged['keywordLocations'] = locations
        entries.each do |entry|
          siblings = entry.fetch(:parent).fetch('errors')
          siblings.delete(entry.fetch(:leaf))
        end
        (unit['errors'] ||= []) << merged
      end
      prune_empty_generic!(branch_units)
    end

    def collect_leaves(unit, branches, leaves)
      (unit['errors'] || []).each do |child|
        if child['reason']
          next
        elsif leaf?(child)
          leaves << { :leaf => child, :parent => unit, :branches => branches }
        else
          collect_leaves(child, branches, leaves)
        end
      end
    end

    def prune_empty_generic!(units)
      units.each do |unit|
        prune_empty_generic!(unit['errors']) if unit['errors']
        prune_branch!(unit) if unit.key?('branchIndex')
      end
    end

    def prune_branch!(branch)
      errors = branch['errors']
      return unless errors
      errors.reject! do |child|
        prune_empty_generic!([child]) unless child['reason']
        !leaf?(child) && child['reason'].nil? && (child['errors'] || []).empty?
      end
      branch.delete('errors') if errors.empty?
    end

    def leaf?(unit)
      !(unit.key?('errors') || unit.key?('annotations'))
    end

    def leaf_key(leaf)
      [
        leaf['type'],
        leaf['error'],
        leaf['instanceLocation'],
        leaf['absoluteKeywordLocation'],
        stable_dump(leaf['details'])
      ]
    end

    def stable_dump(value)
      case value
      when Hash
        value.keys.sort.map { |key| [key.to_s, stable_dump(value.fetch(key))] }.inspect
      when Array
        value.map { |item| stable_dump(item) }.inspect
      else
        value.inspect
      end
    end

    def attach_children(unit, result, limit, branch_index)
      nested = result.nested || []
      if_node = nested.find { |nested_result| nested_result.source.is_a?(Draft202012::Vocab::Applicator::If) }
      nested.each do |nested_result|
        source = nested_result.source
        is_then = source.is_a?(Draft202012::Vocab::Applicator::Then)
        is_else = source.is_a?(Draft202012::Vocab::Applicator::Else)
        if (is_then || is_else) && if_node
          applied = is_then ? if_node.annotation : !if_node.annotation
          target = (applied && !nested_result.valid) ? 'errors' : 'annotations'
          unit[target] ||= []
          unit[target] << build_condition(nested_result, is_then, if_node, limit, branch_index)
        else
          next if nested_result.valid
          unit['errors'] ||= []
          unit['errors'] << build_invalid(nested_result, limit, branch_index)
        end
      end
      if if_node
        add_skipped_condition!(unit, if_node, nested, Draft202012::Vocab::Applicator::Then, true, limit)
        add_skipped_condition!(unit, if_node, nested, Draft202012::Vocab::Applicator::Else, false, limit)
      end
      cap_children(unit, limit)
      unit
    end

    def add_skipped_condition!(unit, if_result, nested, keyword_class, is_then, limit)
      applied = is_then ? if_result.annotation : !if_result.annotation
      return if applied
      keyword_present = if_result.source.schema.parsed.key?(is_then ? 'then' : 'else')
      unit['annotations'] ||= []
      skipped = build_skipped_condition(if_result, is_then, limit, keyword_present)
      unit['annotations'] << skipped if skipped
    end

    def build_skipped_condition(if_result, is_then, limit, present)
      keyword = is_then ? 'then' : 'else'
      return nil unless present
      {
        'valid' => true,
        'keywordLocation' => if_result.send(:resolved_keyword_location).sub(%r{/if\z}, '/' + keyword),
        'absoluteKeywordLocation' => if_result.source.absolute_keyword_location.sub(%r{/if\z}, '/' + keyword),
        'instanceLocation' => if_result.send(:resolved_instance_location),
        'keyword' => keyword,
        'conditionMatched' => false,
        'reason' => is_then ? 'then_not_applied' : 'else_not_applied',
        'condition' => build_condition_unit(if_result, limit)
      }
    end

    def build_condition(result, is_then, if_result, limit, branch_index)
      applied = is_then ? if_result.annotation : !if_result.annotation
      if result.valid
        unit = base_unit(result, true)
      else
        unit = build_condition_failure(result, limit, branch_index)
      end
      unit['keyword'] = is_then ? 'then' : 'else'
      unit['conditionMatched'] = applied
      unit['reason'] = if result.valid
        (is_then ? 'then_schema_passed' : 'else_schema_passed')
      else
        (is_then ? 'then_schema_failed' : 'else_schema_failed')
      end
      unit['condition'] = build_condition_unit(if_result, limit)
      unit['error'] = result.error if applied && !result.valid
      unit
    end

    def build_condition_failure(result, limit, branch_index)
      unit = base_unit(result, false)
      unit['type'] = result.type || CLASSIC_ERROR_TYPES[result.source.class]
      invalid_nested = (result.nested || []).reject(&:valid).map do |nested_result|
        build_invalid(nested_result, limit, branch_index)
      end
      unit['errors'] = invalid_nested
      cap_children(unit, limit)
      unit
    end

    def build_condition_unit(if_result, limit)
      matched = if_result.annotation
      unit = base_unit(if_result, matched)
      unit['keyword'] = 'if'
      unit['conditionMatched'] = matched
      if_subschema_result = if_result.nested&.first
      attach_valid(unit, if_subschema_result, limit) if if_subschema_result
      unit
    end

    def attach_valid(unit, result, limit)
      if result.valid
        (unit['annotations'] ||= []) << build_valid(result, limit)
      else
        unit['errors'] ||= []
        unit['errors'] << build_invalid(result, limit)
      end
      cap_children(unit, limit)
      unit
    end

    # A successful subtree is rendered only where it explains a failure (matched
    # `not`/`oneOf` branches and applied `if` conditions). It is pruned to the
    # matching rule and any nested combination that explains the match.
    def build_valid(result, limit)
      unit = base_unit(result, true)
      nested = result.nested || []
      case result.source
      when Draft202012::Vocab::Applicator::Not
        # Recurse into the matched subschema. For a nested `not` explaining an
        # outer `not` failure this surfaces why the inner `not` matched.
        unit['annotations'] = [build_valid(nested.first, limit)]
      when *BRANCH_KEYWORDS.keys
        unit['keyword'] = BRANCH_KEYWORDS.fetch(result.source.class)
        nested.each_with_index do |nested_result, index|
          next unless nested_result.valid
          branch_unit = build_valid(nested_result, limit)
          branch_unit['branchIndex'] = index
          (unit['annotations'] ||= []) << branch_unit
        end
      else
        nested.each do |nested_result|
          if nested_result.valid
            (unit['annotations'] ||= []) << build_valid(nested_result, limit)
          else
            (unit['errors'] ||= []) << build_invalid(nested_result, limit)
          end
        end
        cap_children(unit, limit)
      end
      unit
    end

    def cap_children(unit, limit)
      if unit.key?('errors')
        unit['errors'] = capped(unit.fetch('errors'), limit, unit, 'errorOmittedCount') { |item| droppable_error?(item) }
        unit.delete('errors') if unit['errors'].empty?
      end
      if unit.key?('annotations')
        unit['annotations'] = capped(unit.fetch('annotations'), limit, unit, 'annotationOmittedCount') { |item| droppable_error?(item) }
        unit.delete('annotations') if unit['annotations'].empty?
      end
    end

    # Combination and condition nodes carry the failure reason and must never
    # be dropped (otherwise truncation could invert the meaning of a failure).
    def droppable_error?(item)
      item['reason'].nil? && !item.key?('branches')
    end

    def capped(items, limit, unit, omitted_key)
      return items unless limit
      return items unless items.size > limit
      droppable_count = items.count { |item| yield(item) }
      budget = limit - (items.size - droppable_count)
      omitted_count = droppable_count - [budget, 0].max
      unit[omitted_key] = omitted_count if omitted_count.positive?
      remaining = [budget, 0].max
      items.each_with_object([]) do |item, out|
        droppable = yield(item)
        if !droppable || remaining.positive?
          out << item
          remaining -= 1 if droppable
        end
      end
    end

    def base_unit(result, valid)
      out = result.to_output_unit
      out['valid'] = valid
      if valid
        out.delete('error')
        out.delete('x-error')
        out.delete('i18n')
      else
        out.delete('annotation')
      end
      out
    end
  end
end
