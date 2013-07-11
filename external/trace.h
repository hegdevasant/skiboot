/* Is this tracebuf empty? */
bool trace_empty(const struct tracebuf *tracebuf);

/* Get the next trace from this buffer (false if empty). */
bool trace_get(union trace *t, struct tracebuf *tb);
