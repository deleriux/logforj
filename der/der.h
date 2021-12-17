#ifndef _DER_H_
#define _DER_H_
#include "errlog.h"
#include <time.h>

#define D_ERRX(f, d, e) { errlog(ERROR, "%s: %s (pos: %d, tag 0x%x)", __FUNCTION__, e, d->pos, d->tag & 0x1f); goto f; }
#define D_ERR(f, d, e) { errlog(ERROR, "%s: %s: %s (pos: %d, tag 0x%x)", __FUNCTION__, e, strerror(errno), d->pos, d->tag & 0x1f); goto f; }

#define D_WARNX(d, e) { errlog(WARNING, "%s: %s (pos: %d)", __FUNCTION__, e, d->pos); }
#define D_WARN(d, e) { errlog(WARNING, "%s: %s: %s (pos: %d)", __FUNCTION__, e, strerror(errno), d->pos); }

#define D_CLASS(d) ((enum tag_class)(d->tag >> 6))
#define D_CONS(d) (d->tag & 0x20)
#define D_TAG(d) ((enum universal_tags)(d->tag & 0x1f))

#define CONS 0x20

enum universal_tags {
  RESERVED0 =         0x0,
  INTEGER =           0x2,
  OID =               0x6,
  SEQUENCE =          0x10,
};

enum tag_class {
  UNIVERSAL = 0,
  APPLICATION = 1,
};

typedef struct der {
  void *handle;
  int pos;
  char *err;
  char *warn;
  int warnlen;

  uint8_t tag;
  int64_t len;

  size_t (*read)(void *, size_t, size_t, void *);
  size_t (*write)(const void *, size_t, size_t, void *);
  size_t (*seek)(void *, long, int);
  long (*tell)(void *);
  int (*fileno)(void *);
  int (*eof)(void *);
  int (*close)(void *);
  int (*error)(void *);
} der_t;

static inline void der_cleartag(der_t *d) { d->tag = -1; d->len = -1; }

/* Basic file handling */
der_t * der_open_from_mem(unsigned char *, size_t);
void der_close(der_t *);
int der_error(der_t *);
int der_warning(der_t *);
const char * der_errstr(der_t *);
const char * der_warnstr(der_t *);

size_t der_read(void *, size_t sz, der_t *);
char der_getc(der_t *);
int der_seek(der_t *, long, int);
long der_tell(der_t *);

bool der_next(der_t *d);
bool der_parse_context(der_t *d, enum tag_class cl, uint8_t tag, bool implicit, int *clen);

/* Universal encoding types -- universal.c */
bool der_parse_integer(der_t *d, int64_t *out);             // 0x02
bool der_parse_oid(der_t *d, char **oid);                   // 0x06
bool der_parse_sequence(der_t *d, int *slen);               // 0x10
#endif
