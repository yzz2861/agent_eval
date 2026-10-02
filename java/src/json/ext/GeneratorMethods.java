/*
 * This code is copyrighted work by Daniel Luz <dev at mernen dot com>.
 *
 * Distributed under the Ruby license: https://www.ruby-lang.org/en/about/license.txt
 */
package json.ext;

import java.lang.ref.WeakReference;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyBoolean;
import org.jruby.RubyFixnum;
import org.jruby.RubyFloat;
import org.jruby.RubyHash;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

/**
 * A class that populates the
 * <code>Json::Ext::Generator::GeneratorMethods</code> module.
 *
 * @author mernen
 */
class GeneratorMethods {
    /**
     * Populates the given module with all modules and their methods
     * @param info The current RuntimeInfo
     * @param module The module to populate
     * (normally <code>JSON::Generator::GeneratorMethods</code>)
     */
    static void populate(RuntimeInfo info, RubyModule module) {
        defineMethods(module, "Array",      RbArray.class);
        defineMethods(module, "FalseClass", RbFalse.class);
        defineMethods(module, "Float",      RbFloat.class);
        defineMethods(module, "Hash",       RbHash.class);
        defineMethods(module, "Integer",    RbInteger.class);
        defineMethods(module, "NilClass",   RbNil.class);
        defineMethods(module, "Object",     RbObject.class);
        defineMethods(module, "String",     RbString.class);
        defineMethods(module, "TrueClass",  RbTrue.class);
    }

    /**
     * Convenience method for defining methods on a submodule.
     * @param parentModule the parent module
     * @param submoduleName the submodule
     * @param klass the class from which to define methods
     */
    private static void defineMethods(RubyModule parentModule,
            String submoduleName, Class<?> klass) {
        RubyModule submodule = parentModule.defineModuleUnder(submoduleName);
        submodule.defineAnnotatedMethods(klass);
    }

    public static class RbHash {
        @JRubyMethod
        public static IRubyObject to_json(ThreadContext context, IRubyObject vSelf) {
            return Generator.generateJson(context, (RubyHash)vSelf, Generator.HASH_HANDLER);
        }

        @JRubyMethod
        public static IRubyObject to_json(ThreadContext context, IRubyObject vSelf, IRubyObject arg0) {
            return Generator.generateJson(context, (RubyHash)vSelf, Generator.HASH_HANDLER, arg0);
        }
    }

    public static class RbArray {
        @JRubyMethod
        public static IRubyObject to_json(ThreadContext context, IRubyObject vSelf) {
            return Generator.generateJson(context, (RubyArray<IRubyObject>)vSelf, Generator.ARRAY_HANDLER);
        }

        @JRubyMethod
        public static IRubyObject to_json(ThreadContext context, IRubyObject vSelf, IRubyObject arg0) {
            return Generator.generateJson(context, (RubyArray<IRubyObject>)vSelf, Generator.ARRAY_HANDLER, arg0);
        }
    }

    public static class RbInteger {
        @JRubyMethod
        public static IRubyObject to_json(ThreadContext context, IRubyObject vSelf) {
            return Generator.generateJson(context, vSelf);
        }

        @JRubyMethod
        public static IRubyObject to_json(ThreadContext context, IRubyObject vSelf, IRubyObject arg0) {
            return Generator.generateJson(context, vSelf, arg0);
        }
    }

    public static class RbFloat {
        @JRubyMethod
        public static IRubyObject to_json(ThreadContext context, IRubyObject vSelf) {
            return Generator.generateJson(context, (RubyFloat)vSelf, Generator.FLOAT_HANDLER);
        }

        @JRubyMethod
        public static IRubyObject to_json(ThreadContext context, IRubyObject vSelf, IRubyObject arg0) {
            return Generator.generateJson(context, (RubyFloat)vSelf, Generator.FLOAT_HANDLER, arg0);
        }
    }

    public static class RbString {
        @JRubyMethod
        public static IRubyObject to_json(ThreadContext context, IRubyObject vSelf) {
            return Generator.generateJson(context, (RubyString)vSelf, Generator.STRING_HANDLER);
        }

        @JRubyMethod
        public static IRubyObject to_json(ThreadContext context, IRubyObject vSelf, IRubyObject arg0) {
            return Generator.generateJson(context, (RubyString)vSelf, Generator.STRING_HANDLER, arg0);
        }
    }

    public static class RbTrue {
        @JRubyMethod
        public static IRubyObject to_json(ThreadContext context, IRubyObject vSelf) {
            return Generator.generateJson(context, (RubyBoolean)vSelf, Generator.TRUE_HANDLER);
        }

        @JRubyMethod
        public static IRubyObject to_json(ThreadContext context, IRubyObject vSelf, IRubyObject arg0) {
            return Generator.generateJson(context, (RubyBoolean)vSelf, Generator.TRUE_HANDLER, arg0);
        }
    }

    public static class RbFalse {
        @JRubyMethod
        public static IRubyObject to_json(ThreadContext context, IRubyObject vSelf) {
            return Generator.generateJson(context, (RubyBoolean)vSelf, Generator.FALSE_HANDLER);
        }

        @JRubyMethod
        public static IRubyObject to_json(ThreadContext context, IRubyObject vSelf, IRubyObject arg0) {
            return Generator.generateJson(context, (RubyBoolean)vSelf, Generator.FALSE_HANDLER, arg0);
        }
    }

    public static class RbNil {
        @JRubyMethod
        public static IRubyObject to_json(ThreadContext context, IRubyObject vSelf) {
            return Generator.generateJson(context, vSelf, Generator.NIL_HANDLER);
        }

        @JRubyMethod
        public static IRubyObject to_json(ThreadContext context, IRubyObject vSelf, IRubyObject arg0) {
            return Generator.generateJson(context, vSelf, Generator.NIL_HANDLER, arg0);
        }
    }

    public static class RbObject {
        @JRubyMethod
        public static IRubyObject to_json(ThreadContext context, IRubyObject self) {
            return RbString.to_json(context, self.asString());
        }

        @JRubyMethod
        public static IRubyObject to_json(ThreadContext context, IRubyObject self, IRubyObject arg0) {
            return RbString.to_json(context, self.asString(), arg0);
        }
    }
}
