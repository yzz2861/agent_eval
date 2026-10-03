# frozen_string_literal: true

module StateMachines
  # Represents a collection of transitions performed together as the result
  # of a single event being dispatched to the orthogonal regions of a
  # parallel state.  Unlike a regular TransitionCollection, all transitions
  # belong to the *same* machine attribute: each one updates a different
  # region within that attribute's encoded configuration value.
  class ParallelTransitionCollection < TransitionCollection
    private

    # Orthogonal region transitions intentionally share the same attribute,
    # so the default uniqueness validation does not apply.
    def validate_attributes!; end

    # Parallel transitions are always performed directly: storing a single
    # event transition on the object would lose the rest of the set.
    def use_event_attributes?
      false
    end
  end
end
