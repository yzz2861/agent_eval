# frozen_string_literal: true

module Test
  class Service
    include Test::Inject["test.client"]
  end
end
