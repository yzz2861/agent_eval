require "English"

module Dotenv
  module Substitutions
    # Substitute variables in a value.
    #
    #   HOST=example.com
    #   URL="https://$HOST"
    #
    module Variable
      class << self
        VARIABLE = /
          (\\)?         # is it escaped with a backslash?
          (\$)          # literal $
          (?!\()        # shouldn't be followed by parenthesis
          \{?           # allow brace wrapping
          ([A-Z0-9_]+)? # optional alpha nums
          \}?           # closing brace
        /xi

        def call(value, env, parent_env = ENV)
          value.gsub(VARIABLE) do |variable|
            match = $LAST_MATCH_INFO

            if match[1] == "\\"
              variable[1..]
            elsif match[3]
              key = match[3]

              if env.key?(key)
                env[key]
              elsif parent_env&.key?(key)
                parent_env[key]
              else
                ""
              end
            else
              variable
            end
          end
        end
      end
    end
  end
end
