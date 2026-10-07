# frozen_string_literal: true
require_relative "file_task"

module Rake

  # A MultiFileTask declares a group of files that are all created by a
  # single action, such as a code generator that writes several files in
  # one run.  All products of the group share the same prerequisites and
  # the same actions.
  #
  # The whole group is rebuilt whenever any product is missing, or when
  # a shared prerequisite is newer than any of the products.  No matter
  # which product is asked for (even concurrently from a multitask), the
  # actions run at most once, and afterwards every declared product must
  # exist.
  #
  # Declare a multi-output task with the +multifile+ DSL method:
  #
  #   multifile ["model.rb", "model.rdoc"] => ["model.src"] do |t|
  #     sh "generate #{t.prerequisites.first}"
  #   end
  #
  # Any product may be used as a prerequisite of other tasks.
  #
  class MultiFileTask < FileTask

    # Shared state coordinating one group of co-produced files.  Every
    # product of a multi-output task belongs to exactly one group; the
    # group decides whether a rebuild is needed and guarantees the
    # shared actions run only once.
    class Group
      # The product tasks (one per declared file) of this group.
      attr_reader :members

      # Has the shared action of this group already run?
      attr_reader :already_invoked

      def initialize(application) # :nodoc:
        @application = application
        @members = []
        @lock = Monitor.new
        @already_invoked = false
      end

      def add_member(member) # :nodoc:
        @members << member
        member.group = self
      end

      # Names of all declared products.
      def names
        @members.map(&:name)
      end

      # Is the group needed?  Yes when any product is missing, or when
      # a shared prerequisite is newer than any of the products.
      def needed?
        return true if @application.options.build_all
        stamps = @members.map(&:timestamp)
        return true if stamps.any? { |stamp| Rake::LATE == stamp }
        out_of_date?(stamps.min)
      end

      # Allow the group to be built again.
      def reenable
        @already_invoked = false
      end

      # Invoke the group on behalf of +representative+, the product
      # task whose invocation triggered this call.  Concurrent
      # invocations of different products block on the group lock, so
      # the shared actions run only once.
      def invoke_with_call_chain(representative, task_args, invocation_chain) # :nodoc:
        @lock.synchronize do
          if @application.options.trace
            @application.trace "** Invoke #{names.join(' ')} (multi-output)"
          end
          return if @already_invoked
          begin
            @already_invoked = true
            representative.invoke_prerequisites(task_args, invocation_chain)
            if needed?
              representative.execute(task_args)
              verify_products! unless @application.options.dryrun
            end
          rescue Exception => ex
            # A failed build must not leave the group in a completed
            # state, so that a later request will try again.
            @already_invoked = false
            representative.send(:add_chain_to, ex, invocation_chain)
            raise ex
          end
        end
      end

      private

      # Are any shared prerequisites newer than the given time stamp?
      def out_of_date?(stamp)
        @members.first.all_prerequisite_tasks.any? { |prereq|
          prereq.timestamp > stamp
        }
      end

      # Every declared product must exist once the actions have run.
      def verify_products!
        missing = @members.reject { |member| File.exist?(member.name) }
        return if missing.empty?
        fail "Multi-output task did not create #{missing.map(&:name).join(', ')}"
      end
    end

    # The group coordinating this product with its siblings.
    attr_reader :group

    def group=(group) # :nodoc:
      @group = group
    end

    # Is this product needed?  A product is needed whenever its whole
    # group needs to be rebuilt.
    def needed?
      @group.needed?
    end

    # Has the shared action of the group already run?
    def already_invoked
      @group.already_invoked
    end

    # Reenable the whole group, allowing it to be built again.
    def reenable
      @group.reenable
    end

    # Invoke this product's group.  The shared actions run only once,
    # no matter which product of the group is invoked.
    #
    # NOTE: this method is public (unlike Task#invoke_with_call_chain)
    # so that any task may invoke a product of the group as a
    # prerequisite.
    def invoke_with_call_chain(task_args, invocation_chain)
      new_chain = Rake::InvocationChain.append(self, invocation_chain)
      @group.invoke_with_call_chain(self, task_args, new_chain)
    end
  end
end
