require "spec_helper"

describe Hamster::RangeMap do
  def runs(values)
    runs = []
    start = nil
    current = nil

    values.each_with_index do |value, point|
      if value
        if start.nil?
          start = point
          current = value
        elsif value != current
          runs << [start, point, current]
          start = point
          current = value
        end
      elsif start
        runs << [start, point, current]
        start = nil
        current = nil
      end
    end
    runs << [start, values.size, current] if start
    runs
  end

  describe "construction" do
    it "starts empty and frozen" do
      map = Hamster::RangeMap.empty
      expect(map).to be_empty
      expect(map.size).to eq(0)
      expect(map.segments).to eq([])
      expect(map).to be_frozen
    end

    it "canonicalizes unsorted adjacent equal segments" do
      map = Hamster::RangeMap.new([
        [10, 12, :d],
        [8, 10, :c],
        [4, 8, :a],
        [0, 4, :a]
      ])
      expect(map.segments).to eq([
        [0, 8, :a],
        [8, 10, :c],
        [10, 12, :d]
      ])
    end

    it "ignores empty input intervals but rejects reversed intervals" do
      expect(Hamster::RangeMap.new([[2, 2, :a]])).to be_empty
      expect {
        Hamster::RangeMap.new([[2, 1, :a]])
      }.to raise_error(ArgumentError)
    end

    it "does not mutate supplied segment arrays" do
      input = [[0, 2, :a], [2, 4, :a]]
      Hamster::RangeMap.new(input)
      expect(input).to eq([[0, 2, :a], [2, 4, :a]])
      expect(input.none?(&:frozen?)).to eq(true)
    end
  end

  describe "#put" do
    it "splits covered segments and keeps the lower endpoint included" do
      map = Hamster::RangeMap.empty.put(0, 10, :a).put(4, 6, :b)
      expect(map.segments).to eq([
        [0, 4, :a],
        [4, 6, :b],
        [6, 10, :a]
      ])
      expect(map.get(3)).to eq(:a)
      expect(map.get(4)).to eq(:b)
      expect(map.get(5)).to eq(:b)
      expect(map.get(6)).to eq(:a)
      expect(map.get(10)).to be_nil
    end

    it "merges adjacent segments only when their values are equal" do
      map = Hamster::RangeMap.empty.put(0, 4, :a).put(4, 8, :b).put(8, 10, :a)
      expect(map.segments).to eq([[0, 4, :a], [4, 8, :b], [8, 10, :a]])

      map = map.put(4, 8, :a)
      expect(map.segments).to eq([[0, 10, :a]])
    end

    it "returns the same map for an empty interval" do
      map = Hamster::RangeMap.empty.put(0, 4, :a)
      expect(map.put(4, 4, :b)).to equal(map)
    end

    it "distinguishes a reversed interval from an empty interval" do
      map = Hamster::RangeMap.empty.put(0, 4, :a)
      expect {
        map.put(4, 0, :b)
      }.to raise_error(ArgumentError, "interval [4, 0) is reversed")
      expect(map.segments).to eq([[0, 4, :a]])
    end
  end

  describe "#clear" do
    it "creates a gap without joining equal surrounding values" do
      map = Hamster::RangeMap.empty.put(0, 10, :a).clear(4, 6)
      expect(map.segments).to eq([[0, 4, :a], [6, 10, :a]])
      expect(map.cover?(5)).to eq(false)
      expect(map.get(5)).to be_nil

      filled = map.put(4, 6, :a)
      expect(filled.segments).to eq([[0, 10, :a]])
    end

    it "clears everything without arguments" do
      map = Hamster::RangeMap.empty.put(0, 10, :a)
      expect(map.clear).to be_empty
      expect(map.segments).to eq([[0, 10, :a]])
    end

    it "is a no-op for an empty interval" do
      map = Hamster::RangeMap.empty.put(0, 10, :a)
      expect(map.clear(4, 4)).to equal(map)
    end
  end

  describe "#each and #segments" do
    it "enumerates only covered fragments within a query interval" do
      map = Hamster::RangeMap[[0, 2, :a], [4, 6, :b]]
      expect(map.segments(1, 5)).to eq([[1, 2, :a], [4, 5, :b]])
      expect(map.each(1, 5).to_a).to eq([[1, 2, :a], [4, 5, :b]])
      expect(map.slice(1, 5).segments).to eq([[1, 2, :a], [4, 5, :b]])
    end

    it "omits gaps from iteration" do
      collected = []
      Hamster::RangeMap[[0, 2, :a], [4, 6, :b]].each { |segment| collected << segment }
      expect(collected).to eq([[0, 2, :a], [4, 6, :b]])
    end

    it "supports one-argument point access and two-argument restriction" do
      map = Hamster::RangeMap[[0, 2, :a], [4, 6, :b]]
      expect(map[1]).to eq(:a)
      expect(map.at(1)).to eq(:a)
      expect(map[1, 5].segments).to eq([[1, 2, :a], [4, 5, :b]])
    end
  end

  describe "#fetch" do
    it "uses the fallback only for gaps" do
      map = Hamster::RangeMap[[0, 2, :a]]
      expect(map.fetch(1, :default)).to eq(:a)
      expect(map.fetch(2, :default)).to eq(:default)
      expect(map.fetch(2) { |point| point }).to eq(2)
      expect { map.fetch(2) }.to raise_error(KeyError)
    end
  end

  describe "custom comparators" do
    it "orders endpoints with a caller-supplied comparator" do
      map = Hamster::RangeMap.empty { |left, right| right <=> left }.put("z", "a", 1)
      expect(map.cover?("m")).to eq(true)
      expect(map.cover?("z")).to eq(true)
      expect(map.cover?("a")).to eq(false)

      split = map.put("m", "f", 2)
      expect(split.segments).to eq([
        ["z", "m", 1],
        ["m", "f", 2],
        ["f", "a", 1]
      ])
    end

    it "accepts a callable as the second argument" do
      comparator = lambda { |left, right| right <=> left }
      map = Hamster::RangeMap.empty(comparator).put("z", "a", 1)
      expect(map.comparator).to equal(comparator)
      expect(map.get("m")).to eq(1)
    end

    it "requires the comparator result to be an integer" do
      map = Hamster::RangeMap.empty(lambda { |_left, _right| nil })
      expect { map.put(1, 2, :a) }.to raise_error(ArgumentError)
    end
  end

  describe "persistence" do
    it "leaves every earlier version unchanged" do
      first = Hamster::RangeMap.empty.put(0, 10, :a)
      second = first.put(4, 6, :b)
      third = second.clear(2, 8)

      expect(first.segments).to eq([[0, 10, :a]])
      expect(second.segments).to eq([[0, 4, :a], [4, 6, :b], [6, 10, :a]])
      expect(third.segments).to eq([[0, 2, :a], [8, 10, :a]])
      expect([first, second, third]).to all(be_frozen)
    end

    it "survives Marshal for naturally ordered endpoints" do
      map = Hamster::RangeMap[[0, 4, :a], [6, 8, :b]]
      loaded = Marshal.load(Marshal.dump(map))
      expect(loaded).to eql(map)
      expect(loaded).to be_frozen
      expect(loaded.put(4, 6, :a).segments).to eq([[0, 6, :a], [6, 8, :b]])
    end

    it "does not marshal maps with a custom comparator" do
      map = Hamster::RangeMap.empty { |left, right| right <=> left }
      expect { Marshal.dump(map) }.to raise_error(TypeError)
    end
  end

  describe "short integer domain" do
    it "matches a point-by-point reference after random updates and removals" do
      map = Hamster::RangeMap.empty
      values = Array.new(16)
      random = Random.new(246810)
      choices = [:a, :b, :c]

      250.times do
        lower = random.rand(17)
        upper = random.rand(17)

        if lower > upper
          expect { map.put(lower, upper, :bad) }.to raise_error(ArgumentError)
          expect { map.clear(lower, upper) }.to raise_error(ArgumentError)
          next
        end

        if random.rand(4).zero?
          map = map.clear(lower, upper)
          (lower...upper).each { |point| values[point] = nil }
        else
          value = choices[random.rand(choices.size)]
          map = map.put(lower, upper, value)
          (lower...upper).each { |point| values[point] = value }
        end

        16.times do |point|
          expect(map.get(point)).to eq(values[point])
          expect(map.cover?(point)).to eq(!values[point].nil?)
        end
        expect(map.segments).to eq(runs(values))
      end

      (0..16).each do |lower|
        (lower..16).each do |upper|
          next if lower == upper
          expected = runs(values).flat_map { |start, finish, value|
            next [] if finish <= lower || start >= upper
            [[[start, lower].max, [finish, upper].min, value]]
          }
          expect(map.segments(lower, upper)).to eq(expected)
          expect(map.slice(lower, upper).segments).to eq(expected)
        end
      end
    end
  end

  describe "large endpoints" do
    it "stores segments rather than expanding every point" do
      start = 0
      finish = 10 ** 10_000
      middle = finish / 2
      quarter = finish / 4
      three_quarters = finish - quarter

      map = Hamster::RangeMap.empty.put(start, finish, :a)
      expect(map.size).to eq(1)

      map = map.put(quarter, three_quarters, :b)
      expect(map.size).to eq(3)
      expect(map.segments).to eq([
        [start, quarter, :a],
        [quarter, three_quarters, :b],
        [three_quarters, finish, :a]
      ])

      map = map.clear(middle, middle + 1)
      expect(map.size).to eq(4)
      expect(map.get(middle)).to be_nil
      expect(map.get(middle - 1)).to eq(:b)
      expect(map.get(middle + 1)).to eq(:b)
    end
  end
end
