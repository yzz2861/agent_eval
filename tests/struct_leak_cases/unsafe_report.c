/*
 * Unsafe construction snippet. Parsed only, never compiled. The public
 * structure is populated by copying the whole internal structure, which
 * drags every internal field (including secret_token) to the report exit.
 */

typedef unsigned long size_t;
void *memcpy(void *destination, const void *source, size_t count);

struct diag_public {
    int id;
    const char *name;
};

struct diag_internal {
    int id;
    const char *name;
    char *secret_token;
};

void host_report(const struct diag_public *report);

void report_by_assignment(struct diag_internal *source)
{
    struct diag_public report;

    /* Whole-structure copy straight out of the internal object. */
    report = *(struct diag_public *)source;

    host_report(&report);
}

void report_by_memcpy(struct diag_internal *source)
{
    struct diag_public report;

    memcpy(&report, source, sizeof(report));

    host_report(&report);
}
