#if !defined(SQLITE3_SNAPSHOT_RUBY) && defined(HAVE_SQLITE3_SNAPSHOT_GET)
#define SQLITE3_SNAPSHOT_RUBY

#include <sqlite3_ruby.h>

struct _sqlite3SnapshotRuby {
    sqlite3_snapshot *p;
};

typedef struct _sqlite3SnapshotRuby sqlite3SnapshotRuby;
typedef sqlite3SnapshotRuby *sqlite3SnapshotRubyPtr;

void init_sqlite3_snapshot();

#endif
