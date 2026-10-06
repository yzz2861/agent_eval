class Parslet::Scope
  # Raised when the accessed slot has never been assigned a value. 
  #
  class NotFound < StandardError
  end
  
  class Binding
    attr_reader :parent
    
    def initialize(parent=nil)
      @parent = parent
      @hash = Hash.new
    end
    
    def [](k)
      @hash.has_key?(k) && @hash[k] ||
        parent && parent[k] or 
        raise NotFound
    end
    def []=(k,v)
      @hash.store(k,v)
    end

    def cache_key
      bindings = @hash.map do |key, value|
        [key, binding_value_key(value)]
      end.sort_by(&:first)

      if @parent
        bindings + [:parent, @parent.cache_key]
      else
        bindings
      end
    end

  private

    def binding_value_key(value)
      case value
      when Parslet::Slice
        [:slice, value.to_str, value.offset]
      when Array
        [:array, value.map { |item| binding_value_key(item) }]
      when Hash
        [:hash, value.map { |key, item| [key, binding_value_key(item)] }.sort]
      when String
        [:string, value]
      else
        if value.respond_to?(:to_slice)
          [:slice_like, value.to_s,
           value.respond_to?(:offset) ? value.offset : nil]
        else
          [:object, value.class, value.object_id]
        end
      end
    end
  end
  
  def [](k)
    @current[k]
  end
  def []=(k,v)
    @current[k] = v
  end
  
  def initialize
    @current = Binding.new
  end
  
  def push
    @current = Binding.new(@current)
  end
  def pop
    @current = @current.parent
  end

  def cache_key
    @current.cache_key
  end

end
