#ifndef SQLITE3_DATABASE_RUBY
#define SQLITE3_DATABASE_RUBY

#include <sqlite3_ruby.h>

/* bits in the `flags` field */
#define SQLITE3_RB_DATABASE_READONLY  0x01
#define SQLITE3_RB_DATABASE_DISCARDED 0x02

struct _sqlite3Ruby {
    VALUE self;
    sqlite3 *db;
    VALUE busy_handler;
    VALUE functions;
    VALUE collations;
    VALUE aggregators;
    VALUE trace_handler;
    VALUE authorizer;
    VALUE authorizer_exception;
    unsigned long authorizer_generation;
    int stmt_timeout;
    struct timespec stmt_deadline;
    rb_pid_t owner;
    int flags;
};

typedef struct _sqlite3Ruby sqlite3Ruby;
typedef sqlite3Ruby *sqlite3RubyPtr;

/* Pinning a collection doesn't pin what's in it, hence both. */
void rb_sqlite3_pin_array_and_contents(VALUE ary);

void init_sqlite3_database();
void set_sqlite3_func_result(sqlite3_context *ctx, VALUE result);

sqlite3RubyPtr sqlite3_database_unwrap(VALUE database);
VALUE sqlite3val2rb(sqlite3_value *val);
unsigned long rb_sqlite3_authorizer_generation(sqlite3RubyPtr ctx);
void rb_sqlite3_authorizer_raise_if_exception(sqlite3RubyPtr ctx);

#endif
