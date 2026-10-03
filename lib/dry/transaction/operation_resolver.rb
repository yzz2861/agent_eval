# frozen_string_literal: true

module Dry
  module Transaction
    class OperationResolver < Module
      def initialize(container)
        module_exec(container) do |ops_container|
          define_method :initialize do |**kwargs|
            definitions = if self.class.respond_to?(:operation_definitions)
                            self.class.operation_definitions
                          else
                            self.class.steps
                          end

            operation_kwargs = definitions.select(&:operation_name).to_h { |step|
              operation = kwargs.fetch(step.name) {
                if step.operation_name.respond_to?(:call)
                  step.operation_name
                elsif kwargs.key?(step.operation_name)
                  kwargs.fetch(step.operation_name)
                elsif ops_container&.key?(step.operation_name)
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
