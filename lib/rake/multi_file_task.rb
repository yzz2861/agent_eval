# frozen_string_literal: true
require_relative "file_task"
require_relative "late_time"

module Rake

  # A MultiFileTask builds a group of file outputs with one action. The group is
  # rebuilt when any output is missing or when a prerequisite is newer than the
  # oldest output.
  #
  class MultiFileTask < FileTask

    # The file names produced by this task.
    attr_accessor :output_names
    alias outputs output_names
    alias products output_names
    alias targets output_names

    # The tasks used to request each individual output.
    attr_accessor :output_tasks

    def initialize(task_name, app)
      super
      @output_names = []
      @output_tasks = []
      @coordination_lock = Monitor.new
      @coordination_condition = @coordination_lock.new_cond
      @coordination_state = :idle
      @coordination_waiters = 0
      @coordination_exception = nil
    end

    # Is this task needed? Yes if any output is missing or out of date.
    def needed?
      return true if @application.options.build_all

      stamp = oldest_output_timestamp
      stamp == Rake::LATE || out_of_date?(stamp)
    end

    # Time stamp for the group, equal to the oldest declared output.
    def timestamp
      oldest_output_timestamp
    end

    # Execute the action and verify that every declared output was created.
    def execute(args=nil)
      super

      return if application.options.dryrun

      missing = output_names.reject { |output_name| File.exist?(output_name) }
      unless missing.empty?
        fail "Multi-file task #{name.inspect} did not create #{missing.join(", ")}"
      end
    end

    def reenable
      @coordination_lock.synchronize do
        @coordination_state = :idle
        @coordination_exception = nil
      end
      super
    end

    def invoke_with_call_chain(task_args, invocation_chain) # :nodoc:
      @coordination_lock.synchronize do
        if @coordination_state == :succeeded
          return
        end

        if [:running, :finishing].include?(@coordination_state)
          @coordination_waiters += 1
          begin
            @coordination_condition.wait_while do
              [:running, :finishing].include?(@coordination_state)
            end
          ensure
            @coordination_waiters -= 1
          end
          raise @coordination_exception if @coordination_exception
          return
        end

        @coordination_state = :running
        @coordination_exception = nil
      end

      begin
        super
      rescue Exception => exception
        finish_coordination(:failed, exception)
        raise
      else
        finish_coordination(:succeeded)
      end
    end

    private

    def finish_coordination(state, exception=nil)
      @coordination_lock.synchronize do
        @coordination_exception = exception
        @coordination_state = :finishing
        @coordination_condition.broadcast
        @coordination_state = state
        @already_invoked = false if state == :failed
        @invocation_exception = nil if state == :failed
        @coordination_condition.broadcast
      end
    end

    def oldest_output_timestamp
      timestamps = output_names.map {
        |output_name|
        begin
          File.mtime(output_name)
        rescue Errno::ENOENT
          Rake::LATE
        end
      }
      return Rake::LATE if timestamps.include?(Rake::LATE)

      timestamps.min
    end

    class << self
      def scope_name(scope, task_name)
        Array(task_name).map {
          |name|
          super(scope, name)
        }
      end
    end
  end

  # Represents one output of a MultiFileTask. Invoking the output delegates to
  # the shared group so concurrent requests only execute its action once.
  class MultiFileOutputTask < FileTask

    attr_reader :multi_file_task
    alias group_task multi_file_task

    def multi_file_task=(task)
      @multi_file_task = task
    end

    def needed?
      multi_file_task.needed?
    end

    def prerequisite_tasks
      multi_file_task.prerequisite_tasks
    end

    def timestamp
      begin
        File.mtime(name)
      rescue Errno::ENOENT
        Rake::LATE
      end
    end

    def already_invoked
      multi_file_task.already_invoked
    end

    def reenable
      multi_file_task.reenable
    end

    def invoke_with_call_chain(task_args, invocation_chain) # :nodoc:
      multi_file_task.invoke_with_call_chain(task_args, invocation_chain)
    end
  end
end
