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

  describe "repeated application" do
    it "continues through passes until no rule is applicable" do
      transformer = Parslet::Transform.new do
        rule(:calculated => simple(:value)) do
          { op: '+', left: Integer(value), right: 3 }
        end
        rule(:op => '+', :left => simple(:left), :right => simple(:right)) do
          left + right
        end
        rule(:op => '*', :left => 1, :right => simple(:right)) { right }
      end

      tree = {
        op: '*',
        left: 1,
        right: { calculated: '4' }
      }

      transformer.apply(tree).should == {
        op: '*',
        left: 1,
        right: { op: '+', left: 4, right: 3 }
      }
      transformer.apply_repeatedly(tree).should == 7
    end

    it "rematches both replacement nodes and affected parents in later passes" do
      transformer = Parslet::Transform.new
      transformer.rule(:add => simple(:value)) { { plus: value } }
      transformer.rule(:plus => simple(:value)) { value + 1 }

      transformer.apply(add: 1).should == { plus: 1 }
      transformer.apply_repeatedly({ add: 1 }).should == 2
    end

    it "raises when rules alternate instead of reaching a fixpoint" do
      transformer = Parslet::Transform.new
      transformer.rule(:form => 'a') { { form: 'b' } }
      transformer.rule(:form => 'b') { { form: 'a' } }

      begin
        transformer.apply_repeatedly({ form: 'a' }, nil, max_transformations: 2)
      rescue Parslet::Transform::RepeatedTransformLimit => error
      else
        fail("Expected RepeatedTransformLimit")
      end

      error.path.should == []
      error.pass.should == 3
      error.transformations.should == 2
      error.max_transformations.should == 2
      error.rule[:index].should == 1
      error.rule[:origin].should == :instance
      error.rule[:expression].should == ({ :form => 'a' }.inspect)
      error.message.should include("[]")
    end

    it "reports the path when a rule keeps creating new nodes" do
      transformer = Parslet::Transform.new
      transformer.rule(:grow => simple(:depth)) do |bindings|
        { grow: bindings[:depth] + 1 }
      end

      begin
        transformer.apply_repeatedly({ outer: { grow: 0 } }, nil, max_transformations: 3)
      rescue Parslet::Transform::RepeatedTransformLimit => error
      else
        fail("Expected RepeatedTransformLimit")
      end

      error.path.should == [:outer]
      error.pass.should == 4
      error.transformations.should == 3
      error.rule[:expression].should == ({ :grow => simple(:depth) }.inspect)
    end

    it "does not invoke the next rule block after the work limit is reached" do
      calls = 0
      transformer = Parslet::Transform.new
      transformer.rule(:grow => simple(:value)) do |bindings|
        calls += 1
        { grow: bindings[:value] + 1 }
      end

      begin
        transformer.apply_repeatedly({ grow: 0 }, nil, max_transformations: 1)
      rescue Parslet::Transform::RepeatedTransformLimit
      else
        fail("Expected RepeatedTransformLimit")
      end

      calls.should == 1
    end

    it "stops on the first match when the work limit is zero" do
      transformer = Parslet::Transform.new
      transformer.rule(:value => simple(:value)) { value + 1 }

      error = begin
        transformer.apply_repeatedly({ value: 0 }, nil, max_transformations: 0)
      rescue Parslet::Transform::RepeatedTransformLimit => error
        error
      else
        fail("Expected RepeatedTransformLimit")
      end

      error.pass.should == 1
      error.transformations.should == 0
      error.max_transformations.should == 0
    end

    it "rejects an invalid work limit" do
      transformer = Parslet::Transform.new

      lambda do
        transformer.apply_repeatedly(0, nil, max_transformations: -1)
      end.should raise_error(ArgumentError, /non-negative Integer/)
    end

    it "prefers instance rules over inherited class rules" do
      base_class = Class.new(Parslet::Transform) do
        rule(:value => simple(:value)) { [:base, value] }
      end
      subclass = Class.new(base_class)
      transformer = subclass.new
      transformer.rule(:value => simple(:value)) { [:instance, value] }

      transformer.apply_repeatedly({ value: 1 }, nil, max_transformations: 1).should == [
        :instance,
        1
      ]
    end

    it "prefers rules defined by a subclass over inherited rules" do
      base_class = Class.new(Parslet::Transform) do
        rule(:value => simple(:value)) { [:base, value] }
      end
      subclass = Class.new(base_class) do
        rule(:value => simple(:value)) { [:subclass, value] }
      end

      subclass.new.apply(value: 1).should == [:subclass, 1]
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
end
