# frozen_string_literal: true

RSpec.describe "Container / Scopes" do
  subject(:container) {
    Class.new(Dry::System::Container) do
      configure do |config|
        config.name = :test
      end
    end
  }

  def closeable(name, closed)
    Class.new do
      define_method(:close) { closed << name }
    end.new
  end

  describe ".scoped" do
    it "returns the block's return value" do
      expect(container.scoped { :result }).to be :result
    end

    it "exposes the scope via .current_scope for the duration of the block" do
      expect(container.current_scope).to be_nil

      container.scoped do |scope|
        expect(container.current_scope).to be scope
      end

      expect(container.current_scope).to be_nil
    end

    it "clears the current scope when the block raises" do
      expect {
        container.scoped { raise "boom" }
      }.to raise_error("boom")

      expect(container.current_scope).to be_nil
    end
  end

  describe "disposal" do
    let(:closed) { [] }

    it "closes owned instances in reverse order of their creation when the scope ends" do
      container.register("first", lifecycle: :scoped) { closeable(:first, closed) }
      container.register("second", lifecycle: :scoped) { closeable(:second, closed) }

      container.scoped do
        container["first"]
        container["second"]
      end

      expect(closed).to eq %i[second first]
    end

    it "disposes owned instances when the block raises" do
      container.register("store", lifecycle: :scoped) { closeable(:store, closed) }

      expect {
        container.scoped {
          container["store"]
          raise "boom"
        }
      }.to raise_error("boom")

      expect(closed).to eq %i[store]
    end

    it "disposes remaining instances when one fails to close, then raises" do
      container.register("failing", lifecycle: :scoped) {
        Class.new do
          def close
            raise "close failed"
          end
        end.new
      }
      container.register("other", lifecycle: :scoped) { closeable(:other, closed) }

      expect {
        container.scoped do
          container["failing"]
          container["other"]
        end
      }.to raise_error("close failed")

      expect(closed).to eq %i[other]
    end

    it "marks the scope as disposed" do
      scope = container.scoped { container.current_scope }

      expect(scope).to be_disposed
    end
  end

  describe "nested scopes" do
    it "inherits instances created in ancestor scopes" do
      container.register("store", lifecycle: :scoped) { Object.new }

      container.scoped do
        outer_instance = container["store"]

        container.scoped do
          expect(container["store"]).to be outer_instance
        end
      end
    end

    it "disposes instances owned by the inner scope when it ends, keeping the outer scope's" do
      closed = []
      container.register("outer_store", lifecycle: :scoped) { closeable(:outer, closed) }
      container.register("inner_store", lifecycle: :scoped) { closeable(:inner, closed) }

      container.scoped do
        container["outer_store"]

        container.scoped do
          container["inner_store"]
        end

        expect(closed).to eq %i[inner]
      end

      expect(closed).to eq %i[inner outer]
    end

    it "does not share instances created in the inner scope with the outer scope" do
      container.register("store", lifecycle: :scoped) { Object.new }

      inner_instance = nil

      container.scoped do
        container.scoped do
          inner_instance = container["store"]
        end

        expect(container["store"]).not_to be inner_instance
      end
    end
  end

  describe "fiber and thread isolation" do
    it "does not expose the scope to other fibers" do
      container.scoped do
        expect(Fiber.new { container.current_scope }.resume).to be_nil
      end
    end

    it "does not expose the scope to other threads" do
      container.scoped do
        expect(Thread.new { container.current_scope }.value).to be_nil
      end
    end

    it "gives each thread its own scoped instances" do
      container.register("store", lifecycle: :scoped) { Object.new }

      instances = 2.times.map {
        Thread.new { container.scoped { container["store"] } }
      }.map(&:value)

      expect(instances.first).not_to be instances.last
    end
  end
end
