# frozen_string_literal: true

require "thread"

RSpec.describe Dry::System::GenerationScope do
  ReloadFailure = Class.new(StandardError)
  Repo = Struct.new(:db, keyword_init: true)
  Service = Struct.new(:repo, :cache, keyword_init: true)

  subject(:scope_manager) { described_class.new(container) }

  let(:events) { Queue.new }

  let(:container) do
    events = self.events

    app = Class.new(Dry::System::Container)
    app.class_eval do
      register_provider(:db) do
        start do
          register(:db, Object.new)
        end

        stop do
          events << :db_stopped
        end
      end

      register_provider(:cache) do
        start do
          register(:cache, Object.new)
        end

        stop do
          events << :cache_stopped
        end
      end

      register(:repo, memoize: true) { Repo.new(db: app[:db]) }
      register(:service, memoize: true) { Service.new(repo: app[:repo], cache: app[:cache]) }
    end
  end

  it "keeps an active scope on the original graph while new scopes use the new graph" do
    ready = Queue.new
    finish_old = Queue.new
    old_result = nil
    old_db = nil

    old_thread = Thread.new do
      scope_manager.use do |scope|
        old_service = scope[:service]
        old_db = old_service.repo.db
        ready << true
        finish_old.pop

        old_result = {
          generation: scope.generation.number,
          service: scope[:service],
          root_service: container[:service],
          db: old_service.repo.db,
          cache: old_service.cache
        }
      end
    end

    ready.pop
    scope_manager.reload!(:db)

    new_result = nil
    new_thread = Thread.new do
      scope_manager.use do |scope|
        service = scope[:service]
        new_result = {
          generation: scope.generation.number,
          service: service,
          root_service: container[:service],
          db: service.repo.db,
          cache: service.cache
        }
      end
    end
    new_thread.join

    expect { events.pop(true) }.to raise_error(ThreadError)

    finish_old << true
    old_thread.join

    expect(new_result[:generation]).to eq(2)
    expect(new_result[:root_service]).to equal(new_result[:service])
    expect(old_result[:generation]).to eq(1)
    expect(old_result[:root_service]).to equal(old_result[:service])
    expect(new_result[:db]).not_to equal(old_db)
    expect(new_result[:service]).not_to equal(old_result[:service])
    expect(new_result[:cache]).to equal(old_result[:cache])
    expect(old_result[:service].repo.db).to equal(old_db)

    expect(events.pop).to eq(:db_stopped)

    scope_manager.use do |scope|
      expect(scope[:cache]).to equal(new_result[:cache])
      expect { events.pop(true) }.to raise_error(ThreadError)
    end

    scope_manager.shutdown!
    expect(events.pop).to eq(:db_stopped)
    expect(events.pop).to eq(:cache_stopped)
    expect { events.pop(true) }.to raise_error(ThreadError)
  end

  it "keeps the current graph available when the replacement graph fails" do
    original_db = scope_manager.use { |scope| scope[:db] }

    expect {
      scope_manager.reload!(:db) do
        raise ReloadFailure, "failure"
      end
    }.to raise_error(ReloadFailure)

    scope_manager.use do |scope|
      expect(scope.generation.number).to eq(1)
      expect(scope[:db]).to equal(original_db)
    end
  end

  it "stops a failed replacement graph and keeps its providers from affecting the old graph", :aggregate_failures do
    scope_manager.use { |scope| scope[:db] }

    container.register_provider(:failing) do
      start do
        target_container.start(:db)
        raise ReloadFailure, "failure"
      end
    end

    expect { scope_manager.reload!(:db, :failing) }.to raise_error(ReloadFailure)

    expect(events.pop(true)).to eq(:db_stopped)
    expect { events.pop(true) }.to raise_error(ThreadError)

    scope_manager.use do |scope|
      expect(scope.generation.number).to eq(1)
      expect(scope[:db]).not_to be_nil
    end

    scope_manager.shutdown!

    expect(events.pop(true)).to eq(:db_stopped)
  end
end
