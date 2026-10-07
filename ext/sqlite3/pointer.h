#ifndef SQLITE3_POINTER_RUBY
#define SQLITE3_POINTER_RUBY

#include <sqlite3_ruby.h>

#ifdef HAVE_SQLITE3_BIND_POINTER
typedef struct sqlite3_ruby_pointer_holder sqlite3_ruby_pointer_holder;

extern VALUE cSqlite3Pointer;
VALUE sqlite3_ruby_pointer_new(sqlite3_ruby_pointer_holder *holder);
int sqlite3_ruby_pointer_wrap(VALUE pointer, sqlite3_stmt *stmt, int index, int *status);
void sqlite3_ruby_pointer_result(VALUE pointer, sqlite3_context *context);
VALUE sqlite3_ruby_value_pointer(sqlite3_value *value);
#else
static inline int
sqlite3_ruby_pointer_wrap(VALUE UNUSED(pointer), sqlite3_stmt *UNUSED(stmt),
                          int UNUSED(index), int *UNUSED(status))
{
    return 0;
}

static inline void
sqlite3_ruby_pointer_result(VALUE UNUSED(pointer), sqlite3_context *UNUSED(context))
{
}

static inline VALUE
sqlite3_ruby_value_pointer(sqlite3_value *UNUSED(value))
{
    return Qundef;
}
#endif

void init_sqlite3_pointer(void);

#endif
