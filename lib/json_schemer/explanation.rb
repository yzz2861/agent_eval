# frozen_string_literal: true
module JSONSchemer
  # Builds an optional, structured explanation of a failed validation.
  #
  # The explanation preserves the anyOf/oneOf/allOf branch tree, merges
  # identical leaf errors, and distinguishes "all branches failed" from
  # "multiple oneOf branches matched". Lists can be capped with a limit;
  # omitted entries are always counted and branch outcomes (which branches
  # matched) are never hidden, so truncation cannot make the failure reason
  # look like its opposite.
  module Explanation
    APPLICATOR = Draft202012::Vocab::Applicator

    class << self
      def build(result, limit: nil)
        return { 'valid' => true } if result.valid
        limit = result.source.schema.root.configuration.explanation_limit if limit.nil?
        explanation = explain_result(result)
        truncate!(explanation, limit) if limit
        { 'valid' => false, 'explanation' => explanation }
      end

    private

      def explain_result(result)
        case result.source
        when APPLICATOR::AnyOf
          combinator_node(result, 'no_branch_matched')
        when APPLICATOR::OneOf
          one_of_node(result)
        when APPLICATOR::AllOf
          combinator_node(result, 'not_all_branches_matched', :failed_only => true)
        when APPLICATOR::Not
          leaf_node(result, 'forbidden_schema_matched')
        when APPLICATOR::Then
          conditional_node(result, 'if_matched_then_failed')
        when APPLICATOR::Else
          conditional_node(result, 'if_not_matched_else_failed')
        else
          generic_node(result)
        end
      end

      def combinator_node(result, reason, failed_only: false)
        node = base_node(result)
        node['reason'] = reason
        branches = result.nested.map.with_index do |branch_result, index|
          branch_node(branch_result, index)
        end
        branches.select! { |branch| !branch['valid'] } if failed_only
        node['branches'] = branches
        node['errors'] = summarize(branches)
        node
      end

      def one_of_node(result)
        matched = []
        branches = result.nested.map.with_index do |branch_result, index|
          matched << index if branch_result.valid
          branch_node(branch_result, index)
        end
        node = base_node(result)
        if matched.size > 1
          node['reason'] = 'multiple_branches_matched'
          node['matchedBranches'] = matched
        else
          node['reason'] = 'no_branch_matched'
        end
        node['branches'] = branches
        node['errors'] = summarize(branches)
        node
      end

      def branch_node(branch_result, index)
        if branch_result.valid
          {
            'branch' => index,
            'valid' => true,
            'instanceLocation' => Location.resolve(branch_result.instance_location),
            'schemaLocation' => Location.resolve(branch_result.keyword_location)
          }
        else
          { 'branch' => index, 'valid' => false }.merge!(explain_result(branch_result))
        end
      end

      def conditional_node(result, reason)
        node = base_node(result)
        node['reason'] = reason
        children = invalid_children(result)
        node['errors'] = merge_leaves(children) if children.any?
        node
      end

      def generic_node(result)
        children = result.ignore_nested ? [] : invalid_children(result)
        if children.empty?
          leaf_node(result)
        else
          node = base_node(result)
          node['errors'] = merge_leaves(children)
          node
        end
      end

      def invalid_children(result)
        return [] unless result.nested
        result.nested.filter_map do |child|
          explain_result(child) unless child.valid
        end
      end

      def base_node(result)
        source = result.source
        node = { 'message' => result.error }
        node['keyword'] = source.keyword if source.is_a?(Keyword)
        node['instanceLocation'] = Location.resolve(result.instance_location)
        node['schemaLocation'] = Location.resolve(result.keyword_location)
        node
      end

      def leaf_node(result, reason = nil)
        node = base_node(result)
        node['reason'] = reason if reason
        node['type'] = result.type || CLASSIC_ERROR_TYPES[result.source.class]
        node['details'] = result.details if result.details
        node
      end

      # Merged leaf summary across the failed branches of a combinator.
      def summarize(branches)
        pairs = []
        branches.each do |branch|
          next if branch['valid']
          collect_leaves(branch).each do |leaf|
            pairs << [branch['branch'], leaf]
          end
        end
        merge_leaves_with_indices(pairs, :branch_indices => true)
      end

      def collect_leaves(node)
        if node.key?('branches')
          node['branches'].flat_map do |branch|
            branch['valid'] ? [] : collect_leaves(branch)
          end
        elsif node.key?('errors')
          node['errors'].flat_map { |child| collect_leaves(child) }
        else
          [node]
        end
      end

      def merge_leaves(nodes)
        merge_leaves_with_indices(nodes.map { |node| [nil, node] })
      end

      def merge_leaves_with_indices(pairs, branch_indices: false)
        entries = []
        entries_by_key = {}
        pairs.each do |branch_index, node|
          unless leaf?(node)
            entries << node
            next
          end
          key = [node['message'], node['instanceLocation'], node['type'], node['details']]
          entry = entries_by_key[key]
          unless entry
            entry = node.dup
            entry.delete('branch')
            entry.delete('valid')
            entry['count'] = 0
            entry['schemaLocations'] = []
            entry['branchIndices'] = [] if branch_indices
            entries_by_key[key] = entry
            entries << entry
          end
          entry['count'] += (node['count'] || 1)
          entry['schemaLocations'] |= Array(node['schemaLocations'] || node['schemaLocation'])
          entry['branchIndices'] |= [branch_index] if branch_indices
        end
        entries.each do |entry|
          next unless entry['count']
          next if entry['count'] > 1
          entry.delete('count')
          entry.delete('schemaLocations')
        end
        entries
      end

      def leaf?(node)
        !node.key?('errors') && !node.key?('branches')
      end

      # Caps branch/error lists at +limit+. Valid branches and structural
      # nodes (combinators, containers) are always kept -- dropping them
      # could make "multiple branches matched" look like "all branches
      # failed" -- and omissions are always counted.
      def truncate!(node, limit)
        if (branches = node['branches'])
          kept = []
          omitted = 0
          invalid_seen = 0
          branches.each do |branch|
            if branch['valid']
              kept << branch
            elsif invalid_seen < limit
              invalid_seen += 1
              kept << branch
            else
              omitted += 1
            end
          end
          node['branches'] = kept
          node['omittedBranches'] = omitted if omitted > 0
          kept.each { |branch| truncate!(branch, limit) unless branch['valid'] }
        end
        if (errors = node['errors'])
          kept = []
          omitted = 0
          leaves_seen = 0
          errors.each do |child|
            if !leaf?(child)
              kept << child
            elsif leaves_seen < limit
              leaves_seen += 1
              kept << child
            else
              omitted += 1
            end
          end
          node['errors'] = kept
          node['omittedErrors'] = omitted if omitted > 0
          kept.each { |child| truncate!(child, limit) }
        end
        node
      end
    end
  end
end
