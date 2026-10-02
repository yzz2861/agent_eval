/*
 * This code is copyrighted work by Daniel Luz <dev at mernen dot com>.
 *
 * Distributed under the Ruby license: https://www.ruby-lang.org/en/about/license.txt
 */
package json.ext;

import java.lang.ref.WeakReference;
import java.util.Map;
import java.util.WeakHashMap;
import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;


final class RuntimeInfo {
    // since the vast majority of cases runs just one runtime,
    // we optimize for that
    private static WeakReference<Ruby> runtime1 = new WeakReference<>(null);
    private static RuntimeInfo info1;
    // store remaining runtimes here (does not include runtime1)
    private static Map<Ruby, RuntimeInfo> runtimes;

    // these fields are filled by the service loaders
    // Use WeakReferences so that RuntimeInfo doesn't indirectly hold a hard reference to
    // the Ruby runtime object, which would cause memory leaks in the runtimes map above.
    /** JSON */
    WeakReference<RubyModule> jsonModule;
    /** JSON::Ext::Generator::State */
    WeakReference<RubyClass> generatorStateClass;

    private RuntimeInfo() {
    }

    static RuntimeInfo initRuntime(Ruby runtime) {
        synchronized (RuntimeInfo.class) {
            if (runtime1.get() == runtime) {
                return info1;
            } else if (runtime1.get() == null) {
                runtime1 = new WeakReference<>(runtime);
                info1 = new RuntimeInfo();
                return info1;
            } else {
                if (runtimes == null) {
                    runtimes = new WeakHashMap<>(1);
                }
                RuntimeInfo cache = runtimes.get(runtime);
                if (cache == null) {
                    cache = new RuntimeInfo();
                    runtimes.put(runtime, cache);
                }
                return cache;
            }
        }
    }

    public static RuntimeInfo forRuntime(Ruby runtime) {
        synchronized (RuntimeInfo.class) {
            if (runtime1.get() == runtime) return info1;
            RuntimeInfo cache = null;
            if (runtimes != null) cache = runtimes.get(runtime);
            assert cache != null : "Runtime given has not initialized JSON::Ext";
            return cache;
        }
    }
}
