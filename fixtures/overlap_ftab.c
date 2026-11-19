/* Overlap demonstration: two analyst ranges claim the same section bytes.
   group_a covers slots 0..1, group_b covers slots 1..2, sharing slot 1. */
extern void alpha(void);
extern void beta(void);

void (* const gtab[3])(void) __attribute__((used)) = {
    alpha,
    beta,
    (void (*)(void))0,
};
