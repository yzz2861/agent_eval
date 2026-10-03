# frozen_string_literal: true

# I18n translation variants are useful when a translation has to be picked
# based on grammatical choice dimensions other than count, e.g. the tone or
# the grammatical person of an invitation email:
#
#   en:
#     invitation:
#       subject:
#         __select__: tone
#         formal: "You are cordially invited"
#         casual: "You're invited!"
#         __default__: "You are invited"
#
# A Hash is only treated as a variant when it carries the explicit
# +__select__+ marker naming the dimension to select on. Plain namespace
# Hashes are never interpreted as variants and keep working as subtrees.
#
# The dimension value is passed as a regular translation option:
#
#   I18n.t(:'invitation.subject', :tone => :formal)
#
# Variants can be nested to select on multiple dimensions, and can be
# combined with pluralization in both directions (a variant branch can hold
# a pluralization Hash and a pluralization leaf can hold a variant):
#
#   en:
#     invitation:
#       body:
#         __select__: tone
#         formal:
#           one: "You are invited to bring %{count} guest"
#           other: "You are invited to bring %{count} guests"
#         casual:
#           __select__: person
#           first: "I saved you %{count} seats"
#           third: "They saved you %{count} seats"
#
# Each variant level can define a +__default__+ branch that is used when no
# matching option was given. When a required option is missing (or does not
# match any branch) and no +__default__+ branch exists, an
# I18n::MissingVariantOption exception is raised, including the lookup path.
#
# Selection always happens before interpolation, so only the finally
# selected String is interpolated.
#
# To enable variants you can simply include the Variants module to the
# Simple backend - or whatever other backend you are using:
#
#   I18n::Backend::Simple.include(I18n::Backend::Variants)
module I18n
  module Backend
    module Variants
      # Marks a Hash as a variant. The value names the dimension to select on.
      SELECT_KEY = :__select__

      # Optional branch used when no option matches any other branch.
      DEFAULT_KEY = :__default__

      protected

      # Overwrites the Base backend select method so that it resolves variant
      # Hashes (marked with +__select__+) interleaved with pluralization
      # Hashes, until a final, non-structured entry is selected.
      def select(locale, key, entry, options)
        resolve_variant(locale, key, entry, options, I18n.normalize_keys(locale, key, options[:scope]))
      end

      private

      def resolve_variant(locale, key, entry, options, path)
        return entry unless entry.is_a?(Hash)

        if (dimension = variant_dimension(entry))
          branch = variant_branch(locale, entry, dimension, options, path)
          resolve_variant(locale, key, entry[branch], options, path + [branch])
        elsif (count = options[:count])
          resolve_variant(locale, key, pluralize(locale, entry, count), options, path)
        else
          entry
        end
      end

      def variant_dimension(entry)
        dimension = entry[SELECT_KEY] || entry[SELECT_KEY.to_s]
        dimension.to_sym if dimension
      end

      def variant_branch(locale, entry, dimension, options, path)
        value = options[dimension]
        branch = variant_fetch(entry, value) unless value.nil?
        branch ||= variant_fetch(entry, DEFAULT_KEY)
        return branch if branch

        raise MissingVariantOption.new(locale, dimension, value, path)
      end

      def variant_fetch(entry, value)
        candidates = [value]
        candidates << value.to_sym if value.respond_to?(:to_sym)
        candidates << value.to_s unless value.is_a?(String)
        candidates.find { |candidate| entry.key?(candidate) }
      end
    end
  end
end
