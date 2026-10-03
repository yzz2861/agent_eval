# frozen_string_literal: true
require 'support'
require 'mustermann/template'

describe Mustermann::Template do
  extend Support::Pattern

  pattern '' do
    it { should     match('')  }
    it { should_not match('/') }

    it { should respond_to(:expand)       }
    it { should respond_to(:to_templates) }
  end

  pattern '/' do
    it { should     match('/')    }
    it { should_not match('/foo') }
  end

  pattern '/foo' do
    it { should     match('/foo')     }
    it { should_not match('/bar')     }
    it { should_not match('/foo.bar') }
  end

  pattern '/foo/bar' do
    it { should     match('/foo/bar')   }
    it { should_not match('/foo%2Fbar') }
    it { should_not match('/foo%2fbar') }
  end

  pattern '/:foo' do
    it { should     match('/:foo')    }
    it { should     match('/%3Afoo')  }
    it { should_not match('/foo')     }
    it { should_not match('/foo?')    }
    it { should_not match('/foo/bar') }
    it { should_not match('/')        }
    it { should_not match('/foo/')    }
  end

  pattern '/föö' do
    it { should match("/f%C3%B6%C3%B6") }
  end

  pattern '/test$/' do
    it { should match('/test$/') }
  end

  pattern '/te+st/' do
    it { should     match('/te+st/') }
    it { should_not match('/test/')  }
    it { should_not match('/teest/') }
  end

  pattern "/path with spaces" do
    it { should match('/path%20with%20spaces') }
    it { should match('/path%2Bwith%2Bspaces') }
    it { should match('/path+with+spaces')     }
  end

  pattern '/foo&bar' do
    it { should match('/foo&bar') }
  end

  pattern '/test.bar' do
    it { should     match('/test.bar') }
    it { should_not match('/test0bar') }
  end

  pattern "/path with spaces", space_matches_plus: false do
    it { should     match('/path%20with%20spaces') }
    it { should_not match('/path%2Bwith%2Bspaces') }
    it { should_not match('/path+with+spaces')     }
  end

  pattern "/path with spaces", uri_decode: false do
    it { should_not match('/path%20with%20spaces') }
    it { should_not match('/path%2Bwith%2Bspaces') }
    it { should_not match('/path+with+spaces')     }
  end

  context 'level 1' do
    context 'without operator' do
      pattern '/hello/{person}' do
        it { should match('/hello/Frank').capturing person: 'Frank' }
        it { should match('/hello/a_b~c').capturing person: 'a_b~c' }
        it { should match('/hello/a.%20').capturing person: 'a.%20' }

        it { should_not match('/hello/:') }
        it { should_not match('/hello//') }
        it { should_not match('/hello/?') }
        it { should_not match('/hello/#') }
        it { should_not match('/hello/[') }
        it { should_not match('/hello/]') }
        it { should_not match('/hello/@') }
        it { should_not match('/hello/!') }
        it { should_not match('/hello/*') }
        it { should_not match('/hello/+') }
        it { should_not match('/hello/,') }
        it { should_not match('/hello/;') }
        it { should_not match('/hello/=') }

        example { pattern.params('/hello/Frank').should be == {'person' => 'Frank'} }
      end

      pattern "/{foo}/{bar}" do
        it { should match('/foo/bar')         .capturing foo: 'foo',     bar: 'bar'     }
        it { should match('/foo.bar/bar.foo') .capturing foo: 'foo.bar', bar: 'bar.foo' }
        it { should match('/10.1/te.st')      .capturing foo: '10.1',    bar: 'te.st'   }
        it { should match('/10.1.2/te.st')    .capturing foo: '10.1.2',  bar: 'te.st'   }

        it { should_not match('/foo%2Fbar') }
        it { should_not match('/foo%2fbar') }
      end
    end
  end

  context 'level 2' do
    context 'operator +' do
      pattern '/hello/{+person}' do
        it { should match('/hello/Frank') .capturing person: 'Frank' }
        it { should match('/hello/a_b~c') .capturing person: 'a_b~c' }
        it { should match('/hello/a.%20') .capturing person: 'a.%20' }
        it { should match('/hello/a/%20') .capturing person: 'a/%20' }
        it { should match('/hello/:')     .capturing person: ?:      }
        it { should match('/hello//')     .capturing person: ?/      }
        it { should match('/hello/?')     .capturing person: ??      }
        it { should match('/hello/#')     .capturing person: ?#      }
        it { should match('/hello/[')     .capturing person: ?[      }
        it { should match('/hello/]')     .capturing person: ?]      }
        it { should match('/hello/@')     .capturing person: ?@      }
        it { should match('/hello/!')     .capturing person: ?!      }
        it { should match('/hello/*')     .capturing person: ?*      }
        it { should match('/hello/+')     .capturing person: ?+      }
        it { should match('/hello/,')     .capturing person: ?,      }
        it { should match('/hello/;')     .capturing person: ?;      }
        it { should match('/hello/=')     .capturing person: ?=      }
      end

      pattern "/{+foo}/{bar}" do
        it { should match('/foo/bar')         .capturing foo: 'foo',     bar: 'bar'     }
        it { should match('/foo.bar/bar.foo') .capturing foo: 'foo.bar', bar: 'bar.foo' }
        it { should match('/foo/bar/bar.foo') .capturing foo: 'foo/bar', bar: 'bar.foo' }
        it { should match('/10.1/te.st')      .capturing foo: '10.1',    bar: 'te.st'   }
        it { should match('/10.1.2/te.st')    .capturing foo: '10.1.2',  bar: 'te.st'   }

        it { should_not match('/foo%2Fbar') }
        it { should_not match('/foo%2fbar') }
      end
    end

    context 'operator #' do
      pattern '/hello/{#person}' do
        it { should match('/hello/#Frank') .capturing person: 'Frank' }
        it { should match('/hello/#a_b~c') .capturing person: 'a_b~c' }
        it { should match('/hello/#a.%20') .capturing person: 'a.%20' }
        it { should match('/hello/#a/%20') .capturing person: 'a/%20' }
        it { should match('/hello/#:')     .capturing person: ?:      }
        it { should match('/hello/#/')     .capturing person: ?/      }
        it { should match('/hello/#?')     .capturing person: ??      }
        it { should match('/hello/##')     .capturing person: ?#      }
        it { should match('/hello/#[')     .capturing person: ?[      }
        it { should match('/hello/#]')     .capturing person: ?]      }
        it { should match('/hello/#@')     .capturing person: ?@      }
        it { should match('/hello/#!')     .capturing person: ?!      }
        it { should match('/hello/#*')     .capturing person: ?*      }
        it { should match('/hello/#+')     .capturing person: ?+      }
        it { should match('/hello/#,')     .capturing person: ?,      }
        it { should match('/hello/#;')     .capturing person: ?;      }
        it { should match('/hello/#=')     .capturing person: ?=      }


        it { should_not match('/hello/Frank') }
        it { should_not match('/hello/a_b~c') }
        it { should_not match('/hello/a.%20') }

        it { should_not match('/hello/:') }
        it { should_not match('/hello//') }
        it { should_not match('/hello/?') }
        it { should_not match('/hello/#') }
        it { should_not match('/hello/[') }
        it { should_not match('/hello/]') }
        it { should_not match('/hello/@') }
        it { should_not match('/hello/!') }
        it { should_not match('/hello/*') }
        it { should_not match('/hello/+') }
        it { should_not match('/hello/,') }
        it { should_not match('/hello/;') }
        it { should_not match('/hello/=') }


        example { pattern.params('/hello/#Frank').should be == {'person' => 'Frank'} }
      end

      pattern "/{+foo}/{#bar}" do
        it { should match('/foo/#bar')         .capturing foo: 'foo',     bar: 'bar'     }
        it { should match('/foo.bar/#bar.foo') .capturing foo: 'foo.bar', bar: 'bar.foo' }
        it { should match('/foo/bar/#bar.foo') .capturing foo: 'foo/bar', bar: 'bar.foo' }
        it { should match('/10.1/#te.st')      .capturing foo: '10.1',    bar: 'te.st'   }
        it { should match('/10.1.2/#te.st')    .capturing foo: '10.1.2',  bar: 'te.st'   }

        it { should_not match('/foo%2F#bar') }
        it { should_not match('/foo%2f#bar') }

        example { pattern.params('/hello/#Frank').should be == {'foo' => 'hello', 'bar' => 'Frank'} }
      end
    end
  end

  context 'level 3' do
    context 'without operator' do
      pattern "{a,b,c}" do
        it { should match("~x,42,_").capturing a: '~x', b: '42', c: '_' }
        it { should_not match("~x,42")      }
        it { should_not match("~x/42")      }
        it { should_not match("~x#42")      }
        it { should_not match("~x,42,_#42") }

        example { pattern.params('d,f,g').should be == {'a' => 'd', 'b' => 'f', 'c' => 'g'} }
      end
    end

    context 'operator +' do
      pattern "{+a,b,c}" do
        it { should match("~x,42,_")     .capturing a: '~x', b: '42', c: '_'     }
        it { should match("~x,42,_#42")  .capturing a: '~x', b: '42', c: '_#42'  }
        it { should match("~/x,42,_/42") .capturing a: '~/x', b: '42', c: '_/42' }

        it { should_not match("~x,42")      }
        it { should_not match("~x/42")      }
        it { should_not match("~x#42")      }
      end
    end

    context 'operator #' do
      pattern "{#a,b,c}" do
        it { should match("#~x,42,_")     .capturing a: '~x', b: '42', c: '_'     }
        it { should match("#~x,42,_#42")  .capturing a: '~x', b: '42', c: '_#42'  }
        it { should match("#~/x,42,_#42") .capturing a: '~/x', b: '42', c: '_#42' }

        it { should_not match("~x,42,_")     }
        it { should_not match("~x,42,_#42")  }
        it { should_not match("~/x,42,_#42") }

        it { should_not match("~x,42")      }
        it { should_not match("~x/42")      }
        it { should_not match("~x#42")      }
      end
    end

    context 'operator .' do
      pattern '/hello/{.person}' do
        it { should match('/hello/.Frank') .capturing person: 'Frank' }
        it { should match('/hello/.a_b~c') .capturing person: 'a_b~c' }

        it { should_not match('/hello/.:') }
        it { should_not match('/hello/./') }
        it { should_not match('/hello/.?') }
        it { should_not match('/hello/.#') }
        it { should_not match('/hello/.[') }
        it { should_not match('/hello/.]') }
        it { should_not match('/hello/.@') }
        it { should_not match('/hello/.!') }
        it { should_not match('/hello/.*') }
        it { should_not match('/hello/.+') }
        it { should_not match('/hello/.,') }
        it { should_not match('/hello/.;') }
        it { should_not match('/hello/.=') }

        it { should_not match('/hello/Frank')  }
        it { should_not match('/hello/a_b~c')  }
        it { should_not match('/hello/a.%20')  }

        it { should_not match('/hello/:') }
        it { should_not match('/hello//') }
        it { should_not match('/hello/?') }
        it { should_not match('/hello/#') }
        it { should_not match('/hello/[') }
        it { should_not match('/hello/]') }
        it { should_not match('/hello/@') }
        it { should_not match('/hello/!') }
        it { should_not match('/hello/*') }
        it { should_not match('/hello/+') }
        it { should_not match('/hello/,') }
        it { should_not match('/hello/;') }
        it { should_not match('/hello/=') }
      end

      pattern "{.a,b,c}" do
        it { should match(".~x.42._").capturing a: '~x', b: '42', c: '_' }
        it { should_not match(".~x,42")   }
        it { should_not match(".~x/42")   }
        it { should_not match(".~x#42")   }
        it { should_not match(".~x,42,_") }
        it { should_not match("~x.42._")  }
      end
    end

    context 'operator /' do
      pattern '/hello{/person}' do
        it { should match('/hello/Frank') .capturing person: 'Frank' }
        it { should match('/hello/a_b~c') .capturing person: 'a_b~c' }

        it { should_not match('/hello//:') }
        it { should_not match('/hello///') }
        it { should_not match('/hello//?') }
        it { should_not match('/hello//#') }
        it { should_not match('/hello//[') }
        it { should_not match('/hello//]') }
        it { should_not match('/hello//@') }
        it { should_not match('/hello//!') }
        it { should_not match('/hello//*') }
        it { should_not match('/hello//+') }
        it { should_not match('/hello//,') }
        it { should_not match('/hello//;') }
        it { should_not match('/hello//=') }

        it { should_not match('/hello/:') }
        it { should_not match('/hello//') }
        it { should_not match('/hello/?') }
        it { should_not match('/hello/#') }
        it { should_not match('/hello/[') }
        it { should_not match('/hello/]') }
        it { should_not match('/hello/@') }
        it { should_not match('/hello/!') }
        it { should_not match('/hello/*') }
        it { should_not match('/hello/+') }
        it { should_not match('/hello/,') }
        it { should_not match('/hello/;') }
        it { should_not match('/hello/=') }
      end

      pattern "{/a,b,c}" do
        it { should match("/~x/42/_").capturing a: '~x', b: '42', c: '_' }
        it { should_not match("/~x,42")   }
        it { should_not match("/~x.42")   }
        it { should_not match("/~x#42")   }
        it { should_not match("/~x,42,_") }
        it { should_not match("~x/42/_")  }
      end
    end

    context 'operator ;' do
      pattern '/hello/{;person}' do
        it { should match('/hello/;person=Frank') .capturing person: 'Frank' }
        it { should match('/hello/;person=a_b~c') .capturing person: 'a_b~c' }
        it { should match('/hello/;person')       .capturing person: nil     }

        it { should_not match('/hello/;persona=Frank') }
        it { should_not match('/hello/;persona=a_b~c') }

        it { should_not match('/hello/;person=:') }
        it { should_not match('/hello/;person=/') }
        it { should_not match('/hello/;person=?') }
        it { should_not match('/hello/;person=#') }
        it { should_not match('/hello/;person=[') }
        it { should_not match('/hello/;person=]') }
        it { should_not match('/hello/;person=@') }
        it { should_not match('/hello/;person=!') }
        it { should_not match('/hello/;person=*') }
        it { should_not match('/hello/;person=+') }
        it { should_not match('/hello/;person=,') }
        it { should_not match('/hello/;person=;') }
        it { should_not match('/hello/;person==') }

        it { should_not match('/hello/;Frank')  }
        it { should_not match('/hello/;a_b~c')  }
        it { should_not match('/hello/;a.%20')  }

        it { should_not match('/hello/:') }
        it { should_not match('/hello//') }
        it { should_not match('/hello/?') }
        it { should_not match('/hello/#') }
        it { should_not match('/hello/[') }
        it { should_not match('/hello/]') }
        it { should_not match('/hello/@') }
        it { should_not match('/hello/!') }
        it { should_not match('/hello/*') }
        it { should_not match('/hello/+') }
        it { should_not match('/hello/,') }
        it { should_not match('/hello/;') }
        it { should_not match('/hello/=') }
      end

      pattern "{;a,b,c}" do
        it { should match(";a=~x;b=42;c=_") .capturing a: '~x', b: '42', c: '_' }
        it { should match(";a=~x;b;c=_")    .capturing a: '~x', b: nil,  c: '_' }

        it { should_not match(";a=~x;c=_;b=42").capturing a: '~x', b: '42', c: '_' }

        it { should_not match(";a=~x;b=42")     }
        it { should_not match("a=~x;b=42")      }
        it { should_not match(";a=~x;b=#42;c")  }
        it { should_not match(";a=~x,b=42,c=_") }
        it { should_not match("~x;b=42;c=_")    }
      end
    end

    context 'operator ?' do
      pattern '/hello/{?person}' do
        it { should match('/hello/?person=Frank') .capturing person: 'Frank' }
        it { should match('/hello/?person=a_b~c') .capturing person: 'a_b~c' }
        it { should match('/hello/?person')       .capturing person: nil     }

        it { should_not match('/hello/?persona=Frank') }
        it { should_not match('/hello/?persona=a_b~c') }

        it { should_not match('/hello/?person=:') }
        it { should_not match('/hello/?person=/') }
        it { should_not match('/hello/?person=?') }
        it { should_not match('/hello/?person=#') }
        it { should_not match('/hello/?person=[') }
        it { should_not match('/hello/?person=]') }
        it { should_not match('/hello/?person=@') }
        it { should_not match('/hello/?person=!') }
        it { should_not match('/hello/?person=*') }
        it { should_not match('/hello/?person=+') }
        it { should_not match('/hello/?person=,') }
        it { should_not match('/hello/?person=;') }
        it { should_not match('/hello/?person==') }

        it { should_not match('/hello/?Frank')  }
        it { should_not match('/hello/?a_b~c')  }
        it { should_not match('/hello/?a.%20')  }

        it { should_not match('/hello/:') }
        it { should_not match('/hello//') }
        it { should_not match('/hello/?') }
        it { should_not match('/hello/#') }
        it { should_not match('/hello/[') }
        it { should_not match('/hello/]') }
        it { should_not match('/hello/@') }
        it { should_not match('/hello/!') }
        it { should_not match('/hello/*') }
        it { should_not match('/hello/+') }
        it { should_not match('/hello/,') }
        it { should_not match('/hello/;') }
        it { should_not match('/hello/=') }
      end

      pattern "{?a,b,c}" do
        it { should match("?a=~x&b=42&c=_") .capturing a: '~x', b: '42', c: '_' }
        it { should match("?a=~x&b&c=_")    .capturing a: '~x', b: nil,  c: '_' }

        it { should_not match("?a=~x&c=_&b=42").capturing a: '~x', b: '42', c: '_' }

        it { should_not match("?a=~x&b=42")     }
        it { should_not match("a=~x&b=42")      }
        it { should_not match("?a=~x&b=#42&c")  }
        it { should_not match("?a=~x,b=42,c=_") }
        it { should_not match("~x&b=42&c=_")    }
      end
    end

    context 'operator &' do
      pattern '/hello/{&person}' do
        it { should match('/hello/&person=Frank') .capturing person: 'Frank' }
        it { should match('/hello/&person=a_b~c') .capturing person: 'a_b~c' }
        it { should match('/hello/&person')       .capturing person: nil     }

        it { should_not match('/hello/&persona=Frank') }
        it { should_not match('/hello/&persona=a_b~c') }

        it { should_not match('/hello/&person=:') }
        it { should_not match('/hello/&person=/') }
        it { should_not match('/hello/&person=?') }
        it { should_not match('/hello/&person=#') }
        it { should_not match('/hello/&person=[') }
        it { should_not match('/hello/&person=]') }
        it { should_not match('/hello/&person=@') }
        it { should_not match('/hello/&person=!') }
        it { should_not match('/hello/&person=*') }
        it { should_not match('/hello/&person=+') }
        it { should_not match('/hello/&person=,') }
        it { should_not match('/hello/&person=;') }
        it { should_not match('/hello/&person==') }

        it { should_not match('/hello/&Frank')  }
        it { should_not match('/hello/&a_b~c')  }
        it { should_not match('/hello/&a.%20')  }

        it { should_not match('/hello/:') }
        it { should_not match('/hello//') }
        it { should_not match('/hello/?') }
        it { should_not match('/hello/#') }
        it { should_not match('/hello/[') }
        it { should_not match('/hello/]') }
        it { should_not match('/hello/@') }
        it { should_not match('/hello/!') }
        it { should_not match('/hello/*') }
        it { should_not match('/hello/+') }
        it { should_not match('/hello/,') }
        it { should_not match('/hello/;') }
        it { should_not match('/hello/=') }
      end

      pattern "{&a,b,c}" do
        it { should match("&a=~x&b=42&c=_") .capturing a: '~x', b: '42', c: '_' }
        it { should match("&a=~x&b&c=_")    .capturing a: '~x', b: nil,  c: '_' }

        it { should_not match("&a=~x&c=_&b=42").capturing a: '~x', b: '42', c: '_' }

        it { should_not match("&a=~x&b=42")     }
        it { should_not match("a=~x&b=42")      }
        it { should_not match("&a=~x&b=#42&c")  }
        it { should_not match("&a=~x,b=42,c=_") }
        it { should_not match("~x&b=42&c=_")    }
      end
    end
  end

  context 'level 4' do
    context 'without operator' do
      context 'prefix' do
        pattern '{a:3}/bar' do
          it { should match('foo/bar') .capturing a: 'foo' }
          it { should match('fo/bar')  .capturing a: 'fo'  }
          it { should match('f/bar')   .capturing a: 'f'   }
          it { should_not match('fooo/bar') }
        end

        pattern '{a:3}{b}' do
          it { should match('foobar') .capturing a: 'foo', b: 'bar' }
        end
      end

      context 'expand' do
        pattern '{a*}' do
          it { should match('a')     .capturing a: 'a'       }
          it { should match('a,b')   .capturing a: 'a,b'     }
          it { should match('a,b,c') .capturing a: 'a,b,c'   }
          it { should_not match('a,b/c') }
          it { should_not match('a,') }

          example { pattern.params('a').should be == { 'a' => ['a'] }}
          example { pattern.params('a,b').should be == { 'a' => ['a', 'b'] }}
        end

        pattern '{a*},{b}' do
          it { should match('a,b')   .capturing a: 'a',   b: 'b' }
          it { should match('a,b,c') .capturing a: 'a,b', b: 'c' }
          it { should_not match('a,b/c') }
          it { should_not match('a,') }

          example { pattern.params('a,b').should be == { 'a' => ['a'], 'b' => 'b' }}
          example { pattern.params('a,b,c').should be == { 'a' => ['a', 'b'], 'b' => 'c' }}
        end

        pattern '{a*,b}' do
          it { should match('a,b')   .capturing a: 'a',   b: 'b' }
          it { should match('a,b,c') .capturing a: 'a,b', b: 'c' }
          it { should_not match('a,b/c') }
          it { should_not match('a,') }

          example { pattern.params('a,b').should be == { 'a' => ['a'], 'b' => 'b' }}
          example { pattern.params('a,b,c').should be == { 'a' => ['a', 'b'], 'b' => 'c' }}
        end
      end
    end

    context 'operator +' do
      pattern '/{a}/{+b}' do
        it { should match('/foo/bar/baz').capturing(a: 'foo', b: 'bar/baz') }
        it { should expand(a: 'foo/bar', b: 'foo/bar').to('/foo%2Fbar/foo/bar') }
      end

      context 'prefix' do
        pattern '{+a:3}/bar' do
          it { should match('foo/bar') .capturing a: 'foo' }
          it { should match('fo/bar')  .capturing a: 'fo'  }
          it { should match('f/bar')   .capturing a: 'f'   }
          it { should_not match('fooo/bar') }
        end

        pattern '{+a:3}{b}' do
          it { should match('foobar') .capturing a: 'foo', b: 'bar' }
        end
      end

      context 'expand' do
        pattern '{+a*}' do
          it { should match('a')     .capturing a: 'a'       }
          it { should match('a,b')   .capturing a: 'a,b'     }
          it { should match('a,b,c') .capturing a: 'a,b,c'   }
          it { should match('a,b/c') .capturing a: 'a,b/c'   }
        end

        pattern '{+a*},{b}' do
          it { should match('a,b')   .capturing a: 'a',   b: 'b' }
          it { should match('a,b,c') .capturing a: 'a,b', b: 'c' }
          it { should_not match('a,b/c') }
          it { should_not match('a,') }

          example { pattern.params('a,b').should be == { 'a' => ['a'], 'b' => 'b' }}
          example { pattern.params('a,b,c').should be == { 'a' => ['a', 'b'], 'b' => 'c' }}
        end
      end
    end

    context 'operator #' do
      context 'prefix' do
        pattern '{#a:3}/bar' do
          it { should match('#foo/bar') .capturing a: 'foo' }
          it { should match('#fo/bar')  .capturing a: 'fo'  }
          it { should match('#f/bar')   .capturing a: 'f'   }
          it { should_not match('#fooo/bar') }
        end

        pattern '{#a:3}{b}' do
          it { should match('#foobar') .capturing a: 'foo', b: 'bar' }
        end
      end

      context 'expand' do
        pattern '{#a*}' do
          it { should match('#a')     .capturing a: 'a'       }
          it { should match('#a,b')   .capturing a: 'a,b'     }
          it { should match('#a,b,c') .capturing a: 'a,b,c'   }
          it { should match('#a,b/c') .capturing a: 'a,b/c'   }

          example { pattern.params('#a,b').should be == { 'a' => ['a', 'b'] }}
          example { pattern.params('#a,b,c').should be == { 'a' => ['a', 'b', 'c'] }}
        end

        pattern '{#a*,b}' do
          it { should match('#a,b')   .capturing a: 'a',   b: 'b' }
          it { should match('#a,b,c') .capturing a: 'a,b', b: 'c' }
          it { should_not match('#a,') }

          example { pattern.params('#a,b').should be == { 'a' => ['a'], 'b' => 'b' }}
          example { pattern.params('#a,b,c').should be == { 'a' => ['a', 'b'], 'b' => 'c' }}
        end
      end
    end

    context 'operator .' do
      context 'prefix' do
        pattern '{.a:3}/bar' do
          it { should match('.foo/bar') .capturing a: 'foo' }
          it { should match('.fo/bar')  .capturing a: 'fo'  }
          it { should match('.f/bar')   .capturing a: 'f'   }
          it { should_not match('.fooo/bar') }
        end

        pattern '{.a:3}{b}' do
          it { should match('.foobar') .capturing a: 'foo', b: 'bar' }
        end
      end

      context 'expand' do
        pattern '{.a*}' do
          it { should match('.a')     .capturing a: 'a'       }
          it { should match('.a.b')   .capturing a: 'a.b'     }
          it { should match('.a.b.c') .capturing a: 'a.b.c'   }
          it { should_not match('.a.b,c') }
          it { should_not match('.a,') }
        end

        pattern '{.a*,b}' do
          it { should match('.a.b')   .capturing a: 'a',   b: 'b' }
          it { should match('.a.b.c') .capturing a: 'a.b', b: 'c' }
          it { should_not match('.a.b/c') }
          it { should_not match('.a.') }

          example { pattern.params('.a.b').should be == { 'a' => ['a'], 'b' => 'b' }}
          example { pattern.params('.a.b.c').should be == { 'a' => ['a', 'b'], 'b' => 'c' }}
        end
      end
    end

    context 'operator /' do
      context 'prefix' do
        pattern '{/a:3}/bar' do
          it { should match('/foo/bar') .capturing a: 'foo' }
          it { should match('/fo/bar')  .capturing a: 'fo'  }
          it { should match('/f/bar')   .capturing a: 'f'   }
          it { should_not match('/fooo/bar') }
        end

        pattern '{/a:3}{b}' do
          it { should match('/foobar') .capturing a: 'foo', b: 'bar' }
        end
      end

      context 'expand' do
        pattern '{/a*}' do
          it { should match('/a')     .capturing a: 'a'       }
          it { should match('/a/b')   .capturing a: 'a/b'     }
          it { should match('/a/b/c') .capturing a: 'a/b/c'   }
          it { should_not match('/a/b,c') }
          it { should_not match('/a,') }
        end

        pattern '{/a*,b}' do
          it { should match('/a/b')   .capturing a: 'a',   b: 'b' }
          it { should match('/a/b/c') .capturing a: 'a/b', b: 'c' }
          it { should_not match('/a/b,c') }
          it { should_not match('/a/') }

          example { pattern.params('/a/b').should be == { 'a' => ['a'], 'b' => 'b' }}
          example { pattern.params('/a/b/c').should be == { 'a' => ['a', 'b'], 'b' => 'c' }}
        end
      end
    end

    context 'operator ;' do
      context 'prefix' do
        pattern '{;a:3}/bar' do
          it { should match(';a=foo/bar') .capturing a: 'foo' }
          it { should match(';a=fo/bar')  .capturing a: 'fo'  }
          it { should match(';a=f/bar')   .capturing a: 'f'   }
          it { should_not match(';a=fooo/bar') }
        end

        pattern '{;a:3}{b}' do
          it { should match(';a=foobar') .capturing a: 'foo', b: 'bar' }
        end
      end

      context 'expand' do
        pattern '{;a*}' do
          it { should match(';a=1')         .capturing a: 'a=1'           }
          it { should match(';a=1;a=2')     .capturing a: 'a=1;a=2'       }
          it { should match(';a=1;a=2;a=3') .capturing a: 'a=1;a=2;a=3'   }
          it { should_not match(';a=1;a=2;b=3') }
          it { should_not match(';a=1;a=2;a=3,') }
        end

        pattern '{;a*,b}' do
          it { should match(';a=1;b')       .capturing a: 'a=1',     b: nil }
          it { should match(';a=2;a=2;b=1') .capturing a: 'a=2;a=2', b: '1' }
          it { should_not match(';a;b;c') }
          it { should_not match(';a;') }

          example { pattern.params(';a=2;a=2;b').should be == { 'a' => ['2', '2'], 'b' => nil }}
        end
      end
    end

    context 'operator ?' do
      context 'prefix' do
        pattern '{?a:3}/bar' do
          it { should match('?a=foo/bar') .capturing a: 'foo' }
          it { should match('?a=fo/bar')  .capturing a: 'fo'  }
          it { should match('?a=f/bar')   .capturing a: 'f'   }
          it { should_not match('?a=fooo/bar') }
        end

        pattern '{?a:3}{b}' do
          it { should match('?a=foobar') .capturing a: 'foo', b: 'bar' }
        end
      end

      context 'expand' do
        pattern '{?a*}' do
          it { should match('?a=1')         .capturing a: 'a=1'           }
          it { should match('?a=1&a=2')     .capturing a: 'a=1&a=2'       }
          it { should match('?a=1&a=2&a=3') .capturing a: 'a=1&a=2&a=3'   }
          it { should_not match('?a=1&a=2&b=3') }
          it { should_not match('?a=1&a=2&a=3,') }
        end

        pattern '{?a*,b}' do
          it { should match('?a=1&b')       .capturing a: 'a=1',     b: nil }
          it { should match('?a=2&a=2&b=1') .capturing a: 'a=2&a=2', b: '1' }
          it { should_not match('?a&b&c') }
          it { should_not match('?a&') }

          example { pattern.params('?a=2&a=2&b').should be == { 'a' => ['2', '2'], 'b' => nil }}
        end
      end
    end

    context 'operator &' do
      context 'prefix' do
        pattern '{&a:3}/bar' do
          it { should match('&a=foo/bar') .capturing a: 'foo' }
          it { should match('&a=fo/bar')  .capturing a: 'fo'  }
          it { should match('&a=f/bar')   .capturing a: 'f'   }
          it { should_not match('&a=fooo/bar') }
        end

        pattern '{&a:3}{b}' do
          it { should match('&a=foobar') .capturing a: 'foo', b: 'bar' }
        end
      end

      context 'expand' do
        pattern '{&a*}' do
          it { should match('&a=1')         .capturing a: 'a=1'           }
          it { should match('&a=1&a=2')     .capturing a: 'a=1&a=2'       }
          it { should match('&a=1&a=2&a=3') .capturing a: 'a=1&a=2&a=3'   }
          it { should_not match('&a=1&a=2&b=3') }
          it { should_not match('&a=1&a=2&a=3,') }
        end

        pattern '{&a*,b}' do
          it { should match('&a=1&b')       .capturing a: 'a=1',     b: nil }
          it { should match('&a=2&a=2&b=1') .capturing a: 'a=2&a=2', b: '1' }
          it { should_not match('&a&b&c') }
          it { should_not match('&a&') }

          example { pattern.params('&a=2&a=2&b').should be == { 'a' => ['2', '2'], 'b' => nil }}
          example { pattern.params('&a=2&a=%20&b').should be == { 'a' => ['2', ' '], 'b' => nil }}
        end
      end
    end
  end

  context 'invalid syntax' do
    example 'unexpected closing bracket' do
      expect { Mustermann::Template.new('foo}bar') }.
        to raise_error(Mustermann::ParseError, 'unexpected } while parsing "foo}bar"')
    end

    example 'missing closing bracket' do
      expect { Mustermann::Template.new('foo{bar') }.
        to raise_error(Mustermann::ParseError, 'unexpected end of string while parsing "foo{bar"')
    end
  end

  context "peeking" do
    subject(:pattern) { Mustermann::Template.new("{name}bar") }

    describe :peek_size do
      example { pattern.peek_size("foo%20bar/blah") .should be == "foo%20bar".size }
      example { pattern.peek_size("/foo bar")       .should be_nil }
    end

    describe :peek_match do
      example { pattern.peek_match("foo%20bar/blah") .to_s .should be == "foo%20bar" }
      example { pattern.peek_match("/foo bar")             .should be_nil }
    end

    describe :peek_params do
      example { pattern.peek_params("foo%20bar/blah") .should be == [{"name" => "foo "}, "foo%20bar".size] }
      example { pattern.peek_params("/foo bar")       .should be_nil }
    end
  end

  describe :partial_expand do
    def partially(pattern, **values)
      Mustermann::Template.new(pattern).partial_expand(values)
    end

    def round_trip(pattern, first, second)
      original = Mustermann::Template.new(pattern)
      partial  = original.partial_expand(first)
      final    = partial.expand(second)
      full     = original.expand(**first, **second)
      [partial, final, full, original === final]
    end

    example { Mustermann::Template.new('/{a}').should respond_to(:partial_expand) }

    context 'return value' do
      subject(:partial) { partially('/{a}/{b}', a: 'foo') }

      example { partial.should be_a(Mustermann::Template) }
      example { partial.to_s.should be == '/foo/{b}' }
      example { partial.expand(b: 'bar').should be == '/foo/bar' }
    end

    context 'string keys' do
      example { partially('/{a}/{b}', 'a' => 'foo').to_s.should be == '/foo/{b}' }
    end

    context 'operators' do
      {
        '{a,b}'   => ['1{,b}',       '1,p%2Fq'],
        '{+a,b}'  => ['1,{+b}',      '1,p/q'],
        '{#a,b}'  => ['#1,{+b}',     '#1,p/q'],
        '{.a,b}'  => ['.1{.b}',      '.1.p%2Fq'],
        '{/a,b}'  => ['/1{/b}',      '/1/p%2Fq'],
        '{;a,b}'  => [';a=1{;b}',    ';a=1;b=p%2Fq'],
        '{?a,b}'  => ['?a=1{&b}',    '?a=1&b=p%2Fq'],
        '{&a,b}'  => ['&a=1{&b}',    '&a=1&b=p%2Fq']
      }.each do |pattern, (partial_string, final_string)|
        example "partially expands #{pattern}" do
          partially(pattern, a: '1').to_s.should be == partial_string
        end

        example "two-step expansion of #{pattern} matches one-step expansion" do
          _, final, full, recognized = round_trip(pattern, { a: '1' }, { b: 'p/q' })
          final.should be == final_string
          final.should be == full
          recognized.should be == true
        end
      end

      example 'keeps unknown query variables in order when none is known' do
        partially('{?a,b}', c: 'x').to_s.should be == '{?a,b}'
      end

      example 'moves unknown query variables into a continuation expression' do
        partially('{?a,b,c}', a: '1', c: '3').to_s.should be == '?a=1&c=3{&b}'
      end

      example 'expands the first known query variable with a ? prefix' do
        partial = partially('{?a,b}', b: '2')
        partial.to_s.should be == '?b=2{&a}'
        partial.expand(a: '1').should be == '?b=2&a=1'
      end

      example 'treats nil values as unknown' do
        partially('{a,b}', a: nil).to_s.should be == '{a,b}'
      end

      example 'supports the semicolon operator without a value' do
        partially('{;a,b}', a: '').to_s.should be == ';a{;b}'
      end
    end

    context 'prefix modifier' do
      example { partially('{x:3}', x: 'hello world').to_s.should be == 'hel' }
    end

    context 'list expansion' do
      example do
        partially('{/list*}', list: ['a', 'b/c', 'd e']).to_s.
          should be == '/a/b%2Fc/d%20e'
      end

      example 'expands a non-exploded list with commas' do
        Mustermann::Template.new('{list}').expand(list: %w[a b]).should be == 'a,b'
      end

      example 'expands an object responding to to_ary as a list' do
        list = Class.new do
          def to_ary = ['a', 'b']
        end.new
        Mustermann::Template.new('{/list*}').expand(list: list).should be == '/a/b'
      end

      example do
        partial, final, full, recognized = round_trip('{/list*,x}',
          { list: ['a', 'b/c'] }, { x: 'z' })
        partial.to_s.should be == '/a/b%2Fc{/x}'
        final.should be == '/a/b%2Fc/z'
        final.should be == full
        recognized.should be == true
      end

      [
        ['{;list*,x}', ';list=a;list=b{;x}', ';list=a;list=b;x=z'],
        ['{?list*,x}', '?list=a&list=b{&x}', '?list=a&list=b&x=z'],
        ['{&list*,x}', '&list=a&list=b{&x}', '&list=a&list=b&x=z'],
        ['{.list*,x}', '.a.b{.x}',           '.a.b.z']
      ].each do |pattern, partial_string, final_string|
        example "expands exploded lists for #{pattern}" do
          partial, final, full, recognized = round_trip(pattern,
            { list: %w[a b] }, { x: 'z' })
          partial.to_s.should be == partial_string
          final.should be == final_string
          final.should be == full
          recognized.should be == true
        end
      end
    end

    context 'map expansion' do
      example do
        partially('{?m*}', m: { 'k1' => 'v 1', 'k2' => 'a/b' }).to_s.
          should be == '?m=k1=v%201&k2=a%2Fb'
      end

      example do
        partially('{m}', m: { 'k1' => 'v1', 'k2' => 'a/b' }).to_s.
          should be == 'k1,v1,k2,a%2Fb'
      end

      example do
        partially('{/m*}', m: { 'a' => '1', 'b' => '2' }).to_s.
          should be == '/a=1/b=2'
      end
    end

    context 'multiple stages' do
      example do
        original = Mustermann::Template.new('/{a}/{b}/{c}{?d,e}')
        first  = original.partial_expand(a: 'x/y')
        second = first.partial_expand(b: 'z')
        final  = second.expand(c: 'w', d: '1', e: '2')
        full   = original.expand(a: 'x/y', b: 'z', c: 'w', d: '1', e: '2')
        first.to_s.should  be == '/x%2Fy/{b}/{c}{?d,e}'
        second.to_s.should be == '/x%2Fy/z/{c}{?d,e}'
        final.should be == full
        (original === final).should be == true
      end
    end

    context 'reserved characters' do
      example do
        partial = partially('{+p}/{q}', p: 'a/b')
        partial.to_s.should be == 'a/b/{q}'
        partial.expand(q: 'c/d').should be == 'a/b/c%2Fd'
      end

      example 'does not re-escape literal text in a later expansion pass' do
        partial = Mustermann::Template.new('{+a}/{b}').partial_expand(a: 'a?b&c=d')
        partial.expand(b: 'x').should be == 'a?b&c=d/x'
      end
    end

    context 'errors' do
      example 'reports an invalid list entry as an expansion error' do
        expect { partially('{list*}', list: [BasicObject.new]) }.
          to raise_error(Mustermann::ExpandError)
      end

      example 'reports an invalid value at the partial expansion stage' do
        expect { partially('/{a}/{b}', a: BasicObject.new) }.
          to raise_error(Mustermann::ExpandError)
      end

      example 'reports an invalid value at the final expansion stage' do
        partial = partially('/{a}/{b}', a: 'x')
        expect { partial.expand(b: BasicObject.new) }.
          to raise_error(Mustermann::ExpandError)
      end

      example 'raises when a value is still missing at final expansion' do
        expect { partially('/{a}/{b}', a: 'x').expand({}) }.
          to raise_error(Mustermann::ExpandError, /b/)
      end
    end

    context 'no values' do
      example { partially('/{a}/{b}').to_s.should be == '/{a}/{b}' }
      example { partially('/{a}/{b}').should be_a(Mustermann::Template) }
    end

    context 'additional value behaviors on direct expansion' do
      subject(:pattern) { Mustermann::Template.new('/{a}{?b}') }

      example 'omits unknown query variables with :ignore' do
        pattern.expand(:ignore, a: 'x', c: 'z').should be == '/x'
      end

      example 'appends extra values with :append' do
        pattern.expand(:append, a: 'x', c: 'hello world').
          should be == '/x?c=hello%20world'
      end

      example 'joins extra values with an ampersand when a query exists' do
        pattern.expand(:append, a: 'x', b: 'y', c: 'z').
          should be == '/x?b=y&c=z'
      end

      example 'escapes reserved characters in appended values' do
        pattern.expand(:append, a: 'x', path: 'a/b?c&d=e').
          should be == '/x?path=a%2Fb%3Fc%26d%3De'
      end

      example 'raises on an unknown behavior' do
        expect { pattern.expand(:bogus, a: 'x') }.to raise_error(ArgumentError)
      end
    end
  end
end
