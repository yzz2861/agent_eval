require "spec_helper"
require "hamster/interval_map"

describe Hamster::IntervalMap do
  DOMAIN = 0...32

  def check_invariants(map)
    fragments = map.to_a
    fragments.each_cons(2) do |left, right|
      expect(left[1]).to be <= right[0]
      if left[1] == right[0]
        expect(left[2]).not_to eq(right[2])
      end
    end
    fragments.each do |start, stop, _value|
      expect(start).to be < stop
    end
  end

  describe "point-by-point comparison with a flat model" do
    it "matches a per-point array over a short integer domain" do
      50.times do
        map      = Hamster::IntervalMap.new
        model    = Array.new(DOMAIN.size)
        versions = [[map, model.dup]]

        100.times do
          start = rand(DOMAIN.size + 1)
          stop  = rand(DOMAIN.size + 1)
          start, stop = stop, start if start > stop
          case rand(3)
          when 0, 1
            value = rand(4)
            map = map.put(start, stop, value)
            model.fill(value, start...stop)
          when 2
            map = map.clear(start, stop)
            model.fill(nil, start...stop)
          end
          versions << [map, model.dup]
        end

        DOMAIN.each do |point|
          expect(map.get(point)).to eq(model[point])
        end
        check_invariants(map)

        expect(map.size).to be <= DOMAIN.size

        versions.each do |old_map, old_model|
          DOMAIN.each do |point|
            expect(old_map.get(point)).to eq(old_model[point])
          end
        end
      end
    end
  end

  describe "very large endpoints" do
    it "stores one fragment per segment, independent of endpoint magnitude" do
      huge = 10**30
      map  = Hamster::IntervalMap.new
      expect(map.size).to eq(0)

      map = map.put(0, huge, :a)
      expect(map.size).to eq(1)

      map = map.put(huge / 3, 2 * (huge / 3), :b)
      expect(map.size).to eq(3)
      expect(map.to_a).to eq([
        [0, huge / 3, :a],
        [huge / 3, 2 * (huge / 3), :b],
        [2 * (huge / 3), huge, :a],
      ])

      expect(map.get(huge - 1)).to eq(:a)
      expect(map.get(huge / 2)).to eq(:b)
      expect(map.get(huge)).to be_nil
      expect(map.get(2 * huge)).to be_nil

      map = map.clear(0, huge)
      expect(map.size).to eq(0)
      expect(map).to be_empty
    end
  end
end
