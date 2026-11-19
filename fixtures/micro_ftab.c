/* Three-slot micro function table.
   slot 0: extern symbol reference -> zero bytes + a relocation entry.
   slot 1: genuinely empty -> zero bytes, no relocation.
   slot 2: deliberately unexplained -> non-zero raw bytes, no relocation. */
extern void firmware_entry(void);

void (* const ftab[3])(void) __attribute__((used)) = {
    firmware_entry,
    (void (*)(void))0,
    (void (*)(void))0x11223344,
};
