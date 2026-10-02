# frozen_string_literal: true

require_relative 'spec_helper'
require_relative 'support/blocking_memory_store'
require_relative 'support/freeze_time_helper'

describe Rack::Attack::Cache do
  it 'keeps reset_count from changing the window of a count in progress' do
    store = BlockingMemoryStore.new
    store.key_pattern = ':1:id'
    cache = Rack::Attack::Cache.new(store: store)

    count_thread = nil
    current_count = nil
    reset_count = nil

    begin
      Timecop.freeze(Time.at(60))
      count_thread = Thread.new { cache.count('id', 60) }
      store.window_started.pop

      Timecop.freeze(Time.at(120))
      cache.reset_count('id', 60)
      store.window_continue << true
      count_thread.join

      current_count = store.read('rack::attack:1:id')
      reset_count = store.read('rack::attack:2:id')
    ensure
      Timecop.return
    end

    _(count_thread.value).must_equal 1
    _(cache.last_epoch_time).must_equal 60
    _(current_count).must_equal 1
    _(reset_count).must_be_nil
  end
end
