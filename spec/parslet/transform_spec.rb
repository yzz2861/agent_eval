require 'spec_helper'

require 'parslet'

describe Parslet::Transform do
  include Parslet
  
  let(:transform) { Parslet::Transform.new }
  
  class A < Struct.new(:elt); end
  class B < Struct.new(:elt); end
  class C < Struct.new(:elt); end
  class Bi < Struct.new(:a, :b); end

  describe "delayed construction" do
    context "given simple(:x) => A.new(x)" do
      before(:each) do
        transform.rule(simple(:x)) { |d| A.new(d[:x]) }
      end

      it "should transform 'a' into A.new('a')" do
        transform.apply('a').should == A.new('a')
      end 
      it "should transform ['a', 'b'] into [A.new('a'), A.new('b')]" do
        transform.apply(['a', 'b']).should == 
          [A.new('a'), A.new('b')]
      end
    end
    context "given rules on {:a => simple(:x)} and {:b => :_x}" do
      before(:each) do
        transform.rule(:a => simple(:x)) { |d| A.new(d[:x]) }
        transform.rule(:b => simple(:x)) { |d| B.new(d[:x]) }
      end

      it "should transform {:d=>{:b=>'c'}} into d => B('c')" do
        transform.apply({:d=>{:b=>'c'}}).should == {:d => B.new('c')}
      end
      it "should transform {:a=>{:b=>'c'}} into A(B('c'))" do
        transform.apply({:a=>{:b=>'c'}}).should == A.new(B.new('c'))
      end
    end
    describe "pulling out subbranches" do
      before(:each) do
        transform.rule(:a => {:b => simple(:x)}, :d => {:e => simple(:y)}) { |d|
          Bi.new(*d.values_at(:x, :y))
        }
      end

      it "should yield Bi.new('c', 'f')" do
        transform.apply(:a => {:b => 'c'}, :d => {:e => 'f'}).should ==
          Bi.new('c', 'f')
      end 
    end
  end
  describe "dsl construction" do
    let(:transform) { Parslet::Transform.new do
        rule(simple(:x)) { A.new(x) }
      end 
    }
    
    it "should still evaluate rules correctly" do
      transform.apply('a').should == A.new('a')
    end 
  end
  describe "class construction" do
    class OptimusPrime < Parslet::Transform 
      rule(:a => simple(:x)) { A.new(x) }
      rule(:b => simple(:x)) { B.new(x) }
    end
    let(:transform) { OptimusPrime.new }
    
    it "should evaluate rules" do
      transform.apply(:a => 'a').should == A.new('a')
    end

    context "optionally raise when no match found" do
      class BumbleBee < Parslet::Transform
        def initialize(&block)
          super(raise_on_unmatch: true, &block)
        end
        rule(:a => simple(:x)) { A.new(x) }
      end
      let(:transform) { BumbleBee.new }

      it "should evaluate rules" do
        transform.apply(:a => 'a').should == A.new('a')
      end

      it "should raise when no rules are matched" do
        lambda {
          transform.apply(:z => 'z')
        }.should raise_error(NotImplementedError, /Failed to match/)
      end
    end

    context "with inheritance" do
      class OptimusPrimeJunior < OptimusPrime
        rule(:b => simple(:x)) { B.new(x.upcase) }
        rule(:c => simple(:x)) { C.new(x) }
      end
      let(:transform) { OptimusPrimeJunior.new }

      it "should inherit rules from its parent" do
        transform.apply(:a => 'a').should == A.new('a')
      end

      it "should be able to override rules from its parent" do
        transform.apply(:b => 'b').should == B.new('B')
      end

      it "should be able to define new rules" do
        transform.apply(:c => 'c').should == C.new('c')
      end
    end
  end
  describe "<- #call_on_match" do
    let(:bindings) { { :foo => 'test' } }
    context "when given a block of arity 1" do
      it "should call the block" do
        called = false
        transform.call_on_match(bindings, lambda do |dict|
          called = true
        end)
        
        called.should == true
      end 
      it "should yield the bindings" do
        transform.call_on_match(bindings, lambda do |dict|
          dict.should == bindings
        end)
      end
      it "should execute in the current context"  do
        foo = 'test'
        transform.call_on_match(bindings, lambda do |dict|
          foo.should == 'test'
        end)
      end
    end
    context "when given a block of arity 0" do
      it "should call the block" do
        called = false
        transform.call_on_match(bindings, proc do 
          called = true
        end)
        
        called.should == true
      end 
      it "should have bindings as local variables" do
        transform.call_on_match(bindings, proc do
          foo.should == 'test'
        end)
      end
      it "should execute in its own context" do
        @bar = 'test'
        transform.call_on_match(bindings, proc do
          if instance_variable_defined?("@bar")
            instance_variable_get("@bar").should_not == 'test'
          end
        end)
      end
    end
  end
  
  context "various transformations (regression)" do
    context "hashes" do
      it "are matched completely" do
        transform.rule(:a => simple(:x)) { fail }
        transform.apply(:a => 'a', :b => 'b')
      end 
    end
  end
  
  context "when not using the bindings as hash, but as local variables" do
    it "should access the variables" do
      transform.rule(simple(:x)) { A.new(x) }
      transform.apply('a').should == A.new('a')
    end
    it "should allow context as local variable" do
      transform.rule(simple(:x)) { foo }
      transform.apply('a', :foo => 'bar').should == 'bar'
    end
  end

  describe "#apply_until_stable" do
    context "chained rules" do
      before(:each) do
        transform.rule(:a => simple(:x)) { {b: x} }
        transform.rule(:b => simple(:x)) { B.new(x) }
      end

      it "keeps #apply a single pass" do
        transform.apply(:a => 1).should == {:b => 1}
      end
      it "repeats until no rule matches anymore" do
        transform.apply_until_stable(:a => 1).should == B.new(1)
      end
      it "returns a tree that no rule applies to anymore" do
        result = transform.apply_until_stable(:a => 1)
        transform.apply(result).should == result
      end
      it "injects context into rule blocks" do
        transform.rule(:c => simple(:x)) { foo }
        transform.apply_until_stable({:c => 1}, :foo => 'bar').should == 'bar'
      end
    end

    context "successive simplification (constant folding)" do
      before(:each) do
        transform.rule(:int => simple(:x)) { Integer(x) }
        transform.rule(:plus => [simple(:a), simple(:b)]) { a + b }
        transform.rule(:times => [simple(:a), 1]) { a }
        transform.rule(:times => [1, simple(:a)]) { a }
      end

      it "adds constants and eliminates multiplication by one" do
        tree = {:times => [{:plus => [{:int => '1'}, {:int => '2'}]}, {:int => '1'}]}
        transform.apply_until_stable(tree).should == 3
      end
    end

    context "replacement results that match again" do
      before(:each) do
        transform.rule(:int => simple(:x)) { {num: Integer(x)} }
        transform.rule(:num => simple(:x)) { x }
      end

      it "needs several passes where #apply stops early" do
        tree = {:neg => {:int => '1'}}
        transform.apply(tree).should == {:neg => {:num => 1}}
        transform.apply_until_stable(tree).should == {:neg => 1}
      end
    end

    context "oscillating rules" do
      before(:each) do
        transform.rule(:x => simple(:v)) { {y: v} }
        transform.rule(:y => simple(:v)) { {x: v} }
      end

      it "raises FixpointError when max_passes is exceeded" do
        expect {
          transform.apply_until_stable({:x => 1}, nil, :max_passes => 5)
        }.to raise_error(Parslet::Transform::FixpointError) { |error|
          error.passes.should == 5
          error.path.should == []
          error.pattern.should be_a(Parslet::Pattern)
          error.message.should include('5 passes')
        }
      end
    end

    context "growing rules" do
      before(:each) do
        transform.rule(:grow => subtree(:v)) { {grow: [v, v]} }
      end

      it "raises FixpointError locating rule and tree path" do
        expect {
          transform.apply_until_stable({:root => [{:grow => 1}]}, nil, :max_applications => 3)
        }.to raise_error(Parslet::Transform::FixpointError) { |error|
          error.applications.should == 4
          error.path.should == [:root, 0]
          error.pattern.inspect.should include('grow')
          error.message.should include('[:root, 0]')
        }
      end
    end

    context "rule precedence" do
      class PrecedenceBase < Parslet::Transform
        rule(:a => simple(:x)) { A.new(x) }
      end

      it "prefers inherited class rules over instance rules" do
        t = PrecedenceBase.new
        t.rule(:a => simple(:x)) { B.new(x) }
        t.apply(:a => 1).should == A.new(1)
        t.apply_until_stable(:a => 1).should == A.new(1)
      end
      it "prefers later defined rules within the same level" do
        transform.rule(:a => simple(:x)) { A.new(x) }
        transform.rule(:a => simple(:x)) { B.new(x) }
        transform.apply_until_stable(:a => 1).should == B.new(1)
      end
    end
  end
end
