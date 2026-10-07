#include <sqlite3_ruby.h>

#ifdef HAVE_SQLITE3_BIND_POINTER

#define SQLITE3_RUBY_POINTER_TYPE "sqlite3-ruby-pointer-v1"
#define SQLITE3_RUBY_POINTER_MAGIC 0x53513350u

struct sqlite3_ruby_pointer_holder {
    VALUE value;
    VALUE type;
    unsigned int references;
    unsigned int initialized;
    unsigned int magic;
};

VALUE cSqlite3Pointer;

static const rb_data_type_t pointer_type;

static sqlite3_ruby_pointer_holder *
pointer_unwrap(VALUE pointer)
{
    sqlite3_ruby_pointer_holder *holder;

    TypedData_Get_Struct(pointer, sqlite3_ruby_pointer_holder, &pointer_type, holder);
    if (holder->magic != SQLITE3_RUBY_POINTER_MAGIC) {
        rb_raise(rb_eRuntimeError, "invalid SQLite3 pointer");
    }
    return holder;
}

static void
pointer_release(sqlite3_ruby_pointer_holder *holder)
{
    holder->references--;
    if (holder->references != 0) { return; }

    rb_gc_unregister_address(&holder->value);
    rb_gc_unregister_address(&holder->type);
    xfree(holder);
}

static void
pointer_deallocate(void *data)
{
    pointer_release((sqlite3_ruby_pointer_holder *)data);
}

static size_t
pointer_memsize(const void *data)
{
    return sizeof(*(const sqlite3_ruby_pointer_holder *)data);
}

static const rb_data_type_t pointer_type = {
    .wrap_struct_name = "SQLite3::Pointer",
    .function = {
        .dfree = pointer_deallocate,
        .dsize = pointer_memsize,
    },
    .flags = RUBY_TYPED_FREE_IMMEDIATELY | RUBY_TYPED_WB_PROTECTED,
};

VALUE
sqlite3_ruby_pointer_new(sqlite3_ruby_pointer_holder *holder)
{
    return TypedData_Wrap_Struct(cSqlite3Pointer, &pointer_type, holder);
}

static VALUE
pointer_allocate(VALUE klass)
{
    sqlite3_ruby_pointer_holder *holder;
    VALUE pointer;

    pointer = TypedData_Make_Struct(klass, sqlite3_ruby_pointer_holder, &pointer_type, holder);
    holder->value = Qnil;
    holder->type = Qnil;
    holder->references = 1;
    holder->initialized = 0;
    holder->magic = SQLITE3_RUBY_POINTER_MAGIC;
    rb_gc_register_address(&holder->value);
    rb_gc_register_address(&holder->type);

    return pointer;
}

static VALUE
normalize_pointer_type(VALUE type)
{
    if (SYMBOL_P(type)) { return rb_sym2str(type); }

    StringValue(type);
    return rb_obj_frozen_p(type) ? type : rb_str_new_frozen(type);
}

static VALUE
pointer_initialize(VALUE self, VALUE type, VALUE value)
{
    sqlite3_ruby_pointer_holder *holder = pointer_unwrap(self);

    if (holder->initialized) {
        rb_raise(rb_eRuntimeError, "cannot initialize a pointer twice");
    }

    type = normalize_pointer_type(type);
    holder->value = value;
    holder->type = type;
    holder->initialized = 1;

    return self;
}

static VALUE
pointer_get_type(VALUE self)
{
    return pointer_unwrap(self)->type;
}

static VALUE
pointer_value_as(VALUE self, VALUE type)
{
    sqlite3_ruby_pointer_holder *holder = pointer_unwrap(self);

    type = normalize_pointer_type(type);
    if (!rb_str_equal(holder->type, type)) { return Qnil; }

    return holder->value;
}

static VALUE
pointer_s_unwrap(int argc, VALUE *argv, VALUE UNUSED(klass))
{
    VALUE pointer, type;

    rb_scan_args(argc, argv, "2", &pointer, &type);
    if (cSqlite3Pointer != CLASS_OF(pointer)) { return Qnil; }

    return pointer_value_as(pointer, type);
}

static VALUE
pointer_inspect(VALUE self)
{
    sqlite3_ruby_pointer_holder *holder = pointer_unwrap(self);

    return rb_sprintf("#<SQLite3::Pointer type=%"PRIsVALUE">", holder->type);
}

int
sqlite3_ruby_pointer_wrap(VALUE pointer, sqlite3_stmt *stmt, int index, int *status)
{
    sqlite3_ruby_pointer_holder *holder;
    int result;

    if (!rb_obj_is_kind_of(pointer, cSqlite3Pointer)) { return 0; }

    holder = pointer_unwrap(pointer);
    holder->references++;
    result = sqlite3_bind_pointer(stmt, index, holder, SQLITE3_RUBY_POINTER_TYPE,
                                  pointer_deallocate);
    if (result != SQLITE_OK) {
        pointer_release(holder);
    }
    *status = result;

    return 1;
}

void
sqlite3_ruby_pointer_result(VALUE pointer, sqlite3_context *context)
{
    sqlite3_ruby_pointer_holder *holder = pointer_unwrap(pointer);

    holder->references++;
    sqlite3_result_pointer(context, holder, SQLITE3_RUBY_POINTER_TYPE,
                           pointer_deallocate);
}

VALUE
sqlite3_ruby_value_pointer(sqlite3_value *value)
{
    sqlite3_ruby_pointer_holder *holder;

    holder = (sqlite3_ruby_pointer_holder *)sqlite3_value_pointer(
                 value, SQLITE3_RUBY_POINTER_TYPE);
    if (holder == NULL || holder->magic != SQLITE3_RUBY_POINTER_MAGIC) { return Qundef; }

    holder->references++;
    return sqlite3_ruby_pointer_new(holder);
}

static void
init_pointer_class(void)
{
    cSqlite3Pointer = rb_define_class_under(mSqlite3, "Pointer", rb_cObject);

    rb_define_alloc_func(cSqlite3Pointer, pointer_allocate);
    rb_define_method(cSqlite3Pointer, "initialize", pointer_initialize, 2);
    rb_define_method(cSqlite3Pointer, "type", pointer_get_type, 0);
    rb_define_method(cSqlite3Pointer, "inspect", pointer_inspect, 0);
    rb_define_singleton_method(cSqlite3Pointer, "get", pointer_s_unwrap, -1);
    rb_undef_method(cSqlite3Pointer, "initialize_copy");
}

#else

static void
init_pointer_class(void)
{
}

#endif

void
init_sqlite3_pointer(void)
{
    init_pointer_class();
}
