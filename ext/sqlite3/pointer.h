#ifndef SQLITE3_RUBY_POINTER
#define SQLITE3_RUBY_POINTER

#include <sqlite3_ruby.h>

/* sqlite3_bind_pointer / sqlite3_result_pointer / sqlite3_value_pointer
 * were introduced in SQLite 3.20.0. */
#if defined(SQLITE_VERSION_NUMBER) && SQLITE_VERSION_NUMBER >= 3020000
#  define HAVE_SQLITE3_POINTER_APIS 1
#endif

extern VALUE cSqlite3Pointer;
extern const rb_data_type_t rb_sqlite3_pointer_data_type;

/* A SQLite3::Pointer wrapper. The wrapper object (and therefore the wrapped
 * Ruby object) is kept alive by an internal registry for exactly as long as
 * SQLite may still dereference the pointer. SQLite's destructor only flips
 * +released+; the memory is reclaimed later by the Ruby GC, so the handoff
 * is safe no matter which side finishes first. */
typedef struct _sqlite3RbPointer {
    VALUE self;         /* the SQLite3::Pointer wrapper object */
    VALUE object;       /* the wrapped Ruby object */
    VALUE type;         /* frozen Ruby String tag */
    const char *c_type; /* interned, pointer-stable C copy of the tag */
    unsigned int refs;  /* number of pointer references SQLite currently holds */
    int released;       /* set when refs reaches 0; memory reclaimed by GC */
} sqlite3RbPointer;

/* The destructor handed to sqlite3_bind_pointer/sqlite3_result_pointer.
 * Only touches C memory, so it is safe from any SQLite callback context. */
void rb_sqlite3_pointer_sqlite_destructor(void *ptr);

/* Intern +type+ (String or Symbol) into a process-lifetime C string. SQLite
 * compares pointer type tags by pointer identity, so every equal tag must
 * resolve to the same C pointer. If +rb_type_out+ is not NULL, it receives a
 * frozen Ruby String copy of the tag. */
const char *rb_sqlite3_pointer_intern_type(VALUE type, VALUE *rb_type_out);

/* Retain +wrapper+ in the internal registry so SQLite's reference keeps the
 * wrapped object alive. Lazily prunes already-released holders. */
void rb_sqlite3_pointer_retain(VALUE wrapper);

/* Drop released holders from the registry. Idempotent; returns the number of
 * holders dropped. */
int rb_sqlite3_pointer_prune(void);

/* If +val+ carries a pointer whose type tag is known to this process, return
 * its SQLite3::Pointer wrapper; otherwise return Qnil. */
VALUE rb_sqlite3_pointer_from_value(sqlite3_value *val);

void init_sqlite3_pointer(void);

#endif
