# frozen_string_literal: true

module Dry
  module Transaction
    class OperationResolver < Module
      def initialize(container)
        module_exec(container) do |ops_container|
          define_method :initialize do |**kwargs|
            definitions = self.class.steps + self.class.recoveries

            operation_kwargs = definitions.select(&:operation_name).uniq(&:name).to_h { |step|
              operation = kwargs.fetch(step.name) {
                if ops_container&.key?(step.operation_name)
                  ops_container[step.operation_name]
                else
                  nil
                end
              }

              [step.name, operation]
            }

            super(**kwargs, **operation_kwargs)
          end
        end
      end
    end
  end
end
