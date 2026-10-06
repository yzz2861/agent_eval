#include <aggregator.h>
#include <database.h>

/* wraps a factory "handler" class. The "-aggregators" instance variable of
 * the SQLite3::Database holds an array of all AggrogatorWrappers.
 *
 * An AggregatorWrapper holds the following instance variables:
 * -handler_klass: the handler that creates the instances.
 * -instances:     array of all the cAggregatorInstance objects currently
 *                 in-flight for this aggregator. */
static VALUE cAggregatorWrapper;

/* wraps a instance of the "handler" class. Loses its reference at the end of
 * the xFinal callback.
 *
 * An AggregatorInstance holds the following instance variables:
 * -handler_instance: the instance to call `step` and `finalize` on.
 * -exc_status:       status returned by rb_protect.
 *                    != 0 if an exception occurred. If an exception occurred
 *                    `step` and `finalize` won't be called any more. */
static VALUE cAggregatorInstance;

typedef struct rb_sqlite3_protected_funcall_args {
    VALUE self;
    ID method;
    int argc;
    VALUE *params;
} protected_funcall_args_t;

/* why isn't there something like this in the ruby API? */
static VALUE
rb_sqlite3_protected_funcall_body(VALUE protected_funcall_args_ptr)
{
    protected_funcall_args_t *args =
        (protected_funcall_args_t *)protected_funcall_args_ptr;

    return rb_funcall2(args->self, args->method, args->argc, args->params);
}

static VALUE
rb_sqlite3_protected_funcall(VALUE self, ID method, int argc, VALUE *params,
                             int *exc_status)
{
    protected_funcall_args_t args = {
        .self = self, .method = method, .argc = argc, .params = params
    };
    return rb_protect(rb_sqlite3_protected_funcall_body, (VALUE)(&args), exc_status);
}

/* called in rb_sqlite3_aggregator_step and rb_sqlite3_aggregator_final. It
 * checks if the execution context already has an associated instance. If it
 * has one, it returns it. If there is no instance yet, it creates one and
 * associates it with the context. */
static VALUE
rb_sqlite3_aggregate_instance(sqlite3_context *ctx)
{
    VALUE aw = (VALUE) sqlite3_user_data(ctx);
    VALUE handler_klass = rb_iv_get(aw, "-handler_klass");
    VALUE inst;
    VALUE *inst_ptr = sqlite3_aggregate_context(ctx, (int)sizeof(VALUE));

    if (!inst_ptr) {
        rb_fatal("SQLite is out-of-memory");
    }

    inst = *inst_ptr;

    if (inst == Qfalse) { /* Qfalse == 0 */
        VALUE instances = rb_iv_get(aw, "-instances");
        int exc_status;

        inst = rb_class_new_instance(0, NULL, cAggregatorInstance);
        rb_iv_set(inst, "-handler_instance", rb_sqlite3_protected_funcall(
                      handler_klass, rb_intern("new"), 0, NULL, &exc_status));
        rb_iv_set(inst, "-exc_status", INT2NUM(exc_status));

        rb_ary_push(instances, inst);

        *inst_ptr = inst;
    }

    if (inst == Qnil) {
        rb_fatal("SQLite called us back on an already destroyed aggregate instance");
    }

    return inst;
}

#if SQLITE_VERSION_NUMBER >= 3025000
/* called by sqlite's xValue callback for window functions. Reads the current
 * value of the window function without destroying the aggregate instance:
 * sqlite calls xValue once per output row and keeps accumulating into the
 * same instance afterwards, so unlike rb_sqlite3_aggregator_final this must
 * not unlink the instance. */
static void
rb_sqlite3_aggregator_value(sqlite3_context *ctx)
{
    VALUE inst = rb_sqlite3_aggregate_instance(ctx);
    VALUE handler_instance = rb_iv_get(inst, "-handler_instance");
    int exc_status = NUM2INT(rb_iv_get(inst, "-exc_status"));

    if (!exc_status) {
        VALUE result = rb_sqlite3_protected_funcall(
                           handler_instance, rb_intern("value"), 0, NULL, &exc_status);
        if (!exc_status) {
            set_sqlite3_func_result(ctx, result);
        }
    }

    if (exc_status) {
        rb_iv_set(inst, "-exc_status", INT2NUM(exc_status));
        sqlite3_result_error(ctx, "Ruby Exception occurred", -1);
    }
}
#endif

/* called by rb_sqlite3_aggregator_final. Unlinks and frees the
 * aggregator_instance_t, so the handler_instance won't be marked any more
 * and Ruby's GC may free it. */
static void
rb_sqlite3_aggregate_instance_destroy(sqlite3_context *ctx)
{
    VALUE aw = (VALUE) sqlite3_user_data(ctx);
    VALUE instances = rb_iv_get(aw, "-instances");
    VALUE *inst_ptr = sqlite3_aggregate_context(ctx, 0);
    VALUE inst;

    if (!inst_ptr || !(inst = *inst_ptr)) {
        return;
    }

    if (inst == Qnil) {
        rb_fatal("attempt to destroy aggregate instance twice");
    }

    rb_iv_set(inst, "-handler_instance", Qnil); // may catch use-after-free
    if (rb_ary_delete(instances, inst) == Qnil) {
        rb_fatal("must be in instances at that point");
    }

    *inst_ptr = Qnil;
}

/* shared implementation of sqlite's xStep and xInverse callbacks. xInverse
 * is only used by window functions: it is called with the same arguments as
 * the matching xStep call when a row leaves the window frame, and must undo
 * the effect of that call. */
static void
rb_sqlite3_aggregator_step_or_inverse(sqlite3_context *ctx, int argc, sqlite3_value **argv, ID method)
{
    VALUE inst = rb_sqlite3_aggregate_instance(ctx);
    VALUE handler_instance = rb_iv_get(inst, "-handler_instance");
    VALUE *params = NULL;
    VALUE params_handle = 0;
    VALUE one_param;
    int exc_status = NUM2INT(rb_iv_get(inst, "-exc_status"));
    int i;

    if (exc_status) {
        return;
    }

    if (argc == 1) {
        one_param = sqlite3val2rb(argv[0]);
        params = &one_param;
    }
    if (argc > 1) {
        /* ALLOCV memory is conservatively marked, so stored VALUEs survive a
         * GC raised by a later sqlite3val2rb call. */
        params = ALLOCV_N(VALUE, params_handle, argc);
        for (i = 0; i < argc; i++) {
            params[i] = sqlite3val2rb(argv[i]);
        }
    }
    rb_sqlite3_protected_funcall(
        handler_instance, method, argc, params, &exc_status);
    if (argc > 1) {
        ALLOCV_END(params_handle);
    }

    rb_iv_set(inst, "-exc_status", INT2NUM(exc_status));
}

static void
rb_sqlite3_aggregator_step(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    rb_sqlite3_aggregator_step_or_inverse(ctx, argc, argv, rb_intern("step"));
}

#if SQLITE_VERSION_NUMBER >= 3025000
static void
rb_sqlite3_aggregator_inverse(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    rb_sqlite3_aggregator_step_or_inverse(ctx, argc, argv, rb_intern("inverse"));
}
#endif

/* we assume that this function is only called once per execution context */
static void
rb_sqlite3_aggregator_final(sqlite3_context *ctx)
{
    VALUE inst = rb_sqlite3_aggregate_instance(ctx);
    VALUE handler_instance = rb_iv_get(inst, "-handler_instance");
    int exc_status = NUM2INT(rb_iv_get(inst, "-exc_status"));

    if (!exc_status) {
        VALUE result = rb_sqlite3_protected_funcall(
                           handler_instance, rb_intern("finalize"), 0, NULL, &exc_status);
        if (!exc_status) {
            set_sqlite3_func_result(ctx, result);
        }
    }

    if (exc_status) {
        /* the user should never see this, as Statement.step() will pick up the
         * outstanding exception and raise it instead of generating a new one
         * for SQLITE_ERROR with message "Ruby Exception occurred" */
        sqlite3_result_error(ctx, "Ruby Exception occurred", -1);
    }

    rb_sqlite3_aggregate_instance_destroy(ctx);
}

static int
rb_sqlite3_aggregator_arity(VALUE self, VALUE aggregator)
{
    int arity;

    if (rb_respond_to(aggregator, rb_intern("arity"))) {
        VALUE ruby_arity = rb_funcall(aggregator, rb_intern("arity"), 0);
        arity = NUM2INT(ruby_arity);
    } else {
        arity = -1;
    }

    if (arity < -1 || arity > 127) {
#ifdef PRIsVALUE
        rb_raise(rb_eArgError, "%"PRIsVALUE" arity=%d out of range -1..127",
                 self, arity);
#else
        rb_raise(rb_eArgError, "Aggregator arity=%d out of range -1..127", arity);
#endif
    }

    return arity;
}

static VALUE
rb_sqlite3_aggregator_wrapper_new(VALUE aggregator)
{
    VALUE aw = rb_class_new_instance(0, NULL, cAggregatorWrapper);

    rb_iv_set(aw, "-handler_klass", aggregator);
    rb_iv_set(aw, "-instances", rb_ary_new());

    return aw;
}

/* remembers the wrapper on the database, so the handler and its in-flight
 * instances stay reachable (and pinned) for as long as sqlite may call back
 * into them. Only call this after the function was successfully created. */
static void
rb_sqlite3_aggregator_wrapper_register(VALUE self, sqlite3RubyPtr ctx, VALUE aw)
{
    VALUE aggregators;

    if (!rb_ivar_defined(self, rb_intern("-aggregators"))) {
        rb_iv_set(self, "-aggregators", rb_ary_new());
    }
    aggregators = rb_iv_get(self, "-aggregators");

    rb_ary_push(aggregators, aw);
    RB_OBJ_WRITE(self, &ctx->aggregators, aggregators);
}

/* call-seq: define_aggregator2(aggregator)
 *
 * Define an aggregate function according to a factory object (the "handler")
 * that knows how to obtain to all the information. The handler must provide
 * the following class methods:
 *
 * +arity+:: corresponds to the +arity+ parameter of #create_aggregate. This
 *           message is optional, and if the handler does not respond to it,
 *           the function will have an arity of -1.
 * +name+:: this is the name of the function. The handler _must_ implement
 *          this message.
 * +new+:: this must be implemented by the handler. It should return a new
 *         instance of the object that will handle a specific invocation of
 *         the function.
 *
 * The handler instance (the object returned by the +new+ message, described
 * above), must respond to the following messages:
 *
 * +step+:: this is the method that will be called for each step of the
 *          aggregate function's evaluation. It should take parameters according
 *          to the *arity* definition.
 * +finalize+:: this is the method that will be called to finalize the
 *              aggregate function's evaluation. It should not take arguments.
 *
 * Note the difference between this function and #create_aggregate_handler
 * is that no FunctionProxy ("ctx") object is involved. This manifests in two
 * ways: The return value of the aggregate function is the return value of
 * +finalize+ and neither +step+ nor +finalize+ take an additional "ctx"
 * parameter.
 */
VALUE
rb_sqlite3_define_aggregator2(VALUE self, VALUE aggregator, VALUE ruby_name)
{
    /* define_aggregator is added as a method to SQLite3::Database in database.c */
    sqlite3RubyPtr ctx = sqlite3_database_unwrap(self);
    int arity, status;
    VALUE aw;

    if (!ctx->db) {
        rb_raise(rb_path2class("SQLite3::Exception"), "cannot use a closed database");
    }

    arity = rb_sqlite3_aggregator_arity(self, aggregator);
    aw = rb_sqlite3_aggregator_wrapper_new(aggregator);

    status = sqlite3_create_function(
                 ctx->db,
                 StringValueCStr(ruby_name),
                 arity,
                 SQLITE_UTF8,
                 (void *)aw,
                 NULL,
                 rb_sqlite3_aggregator_step,
                 rb_sqlite3_aggregator_final
             );

    CHECK(ctx->db, status);

    rb_sqlite3_aggregator_wrapper_register(self, ctx, aw);

    return self;
}

/* call-seq: define_window_function2(aggregator, name)
 *
 * Define a window function according to a factory object (the "handler"),
 * like define_aggregator2. In addition to +step+ and +finalize+, the handler
 * instances must implement the following methods so sqlite can maintain a
 * sliding window incrementally:
 *
 * +inverse+:: called with the same arguments as +step+ when a row leaves the
 *             window frame. It must undo the effect of the matching +step+
 *             call.
 * +value+::   called to read the current value of the window function
 *             without destroying the aggregate instance. sqlite calls it once
 *             per output row; the instance keeps accumulating afterwards.
 *
 * +finalize+ is called exactly once per partition (also when the statement
 * is interrupted or closed early), after which the instance is released.
 */
VALUE
rb_sqlite3_define_window_function2(VALUE self, VALUE aggregator, VALUE ruby_name)
{
    sqlite3RubyPtr ctx = sqlite3_database_unwrap(self);

    if (!ctx->db) {
        rb_raise(rb_path2class("SQLite3::Exception"), "cannot use a closed database");
    }

#if SQLITE_VERSION_NUMBER >= 3025000
    int arity = rb_sqlite3_aggregator_arity(self, aggregator);
    int status;
    VALUE aw = rb_sqlite3_aggregator_wrapper_new(aggregator);

    status = sqlite3_create_window_function(
                 ctx->db,
                 StringValueCStr(ruby_name),
                 arity,
                 SQLITE_UTF8,
                 (void *)aw,
                 rb_sqlite3_aggregator_step,
                 rb_sqlite3_aggregator_final,
                 rb_sqlite3_aggregator_value,
                 rb_sqlite3_aggregator_inverse,
                 NULL
             );

    CHECK(ctx->db, status);

    rb_sqlite3_aggregator_wrapper_register(self, ctx, aw);

    return self;
#else
    rb_raise(rb_eNotImpError, "window functions require SQLite 3.25.0 or later");
#endif
}

void
rb_sqlite3_aggregator_pin_instances(VALUE aw)
{
    rb_sqlite3_pin_array_and_contents(rb_iv_get(aw, "-instances"));
}

void
rb_sqlite3_aggregator_init(void)
{
    /* rb_class_new generatos class with undefined allocator in ruby 1.9 */
    cAggregatorWrapper = rb_funcall(rb_cClass, rb_intern("new"), 0);
    rb_gc_register_mark_object(cAggregatorWrapper);

    cAggregatorInstance = rb_funcall(rb_cClass, rb_intern("new"), 0);
    rb_gc_register_mark_object(cAggregatorInstance);
}
