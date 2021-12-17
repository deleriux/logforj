#include "common.h"
#include <stdarg.h>
#include "der.h"

struct der_mbuf {
  unsigned char *buf;
  size_t len;
  off_t pos;
};

static size_t der_mbread(
    void *b,
    size_t s,
    size_t n,
    void *h)
{
  struct der_mbuf *mb = (struct der_mbuf *)h;
  char *p = mb->buf + mb->pos;
  memcpy(b, p, (s*n));
  mb->pos += (s*n);
  return n;
}

static size_t der_mbwrite(
    const void *b,
    size_t s,
    size_t n,
    void *h)
{
  struct der_mbuf *mb = (struct der_mbuf *)h;
  errno = EROFS;
  return 0;
}

static size_t der_mbseek(
    void *h,
    long p,
    int w)
{
  struct der_mbuf *mb = (struct der_mbuf *)h;
  switch (w) {
    case SEEK_SET:
      mb->pos = p;
      return mb->pos;
    break;
    case SEEK_CUR:
      if ((mb->pos + p) < 0) {
        errno = EINVAL;
        return -1;
      }
      mb->pos += p;
      return mb->pos;
    break;
    case SEEK_END:
      if ((mb->len + p) < 0) {
        errno = EINVAL;
        return -1;
      }
    break;

    default:
      errno = EINVAL;
      return -1;
    break;
  }
}

static long der_mbtell(
    void *h)
{
  struct der_mbuf *mb = (struct der_mbuf *)h;
  return mb->pos;
}

static int der_mbfileno(
    void *h)
{
  errno = ENOTSUP;
  return -1;
}

static int der_mbeof(
    void *h)
{
  struct der_mbuf *mb = (struct der_mbuf *)h;
  if (mb->pos >= mb->len)
    return 1;
  return 0;
}

static int der_mbclose(
    void *h)
{
  struct der_mbuf *mb = (struct der_mbuf *)h;
  free(h);
  return 0;
}

static int der_mberror(
    void *h)
{
  return 0;
}


static size_t der_fread(
    void *b,
    size_t s,
    size_t n,
    void *h)
{
  return fread(b, s, n, (FILE *)h);
}

static size_t der_fwrite(
    const void *b,
    size_t s,
    size_t n,
    void *h)
{
  return fwrite(b, s, n, (FILE *)h);
}

static size_t der_fseek(
    void *h,
    long p,
    int w)
{
  return fseek((FILE *)h, p, w);
}

static long der_ftell(
    void *h)
{
  return ftell((FILE *)h);
}

static int der_ffileno(
    void *h)
{
  return fileno((FILE *)h);
}

static int der_feof(
    void *h)
{
  return feof((FILE *)h);
}

static int der_fclose(
    void *h)
{
  return fclose((FILE *)h);
}

static int der_ferror(
    void *h)
{
  return ferror((FILE *)h);
}

static int64_t get_len(
    der_t *d)
{
  int64_t tot = 0;
  uint8_t size = 0, i, len=0;

  assert(d);

  len = der_getc(d);
  if (der_error(d)) 
    return -1;

  switch(len) {
    // Literal byte size in length 
    case 0x00 ... 0x7f:
      return len;

    // The next few bytes have the literal length
    case 0x80 ... 0x87:
      for (int i=0; i < (len & 0x7f); i++) {
        size = der_getc(d);
        if (der_error(d))
          return -1;
        tot <<= 8;
        tot += size;
      }
      if (tot < 0 || tot > INT64_MAX) {
        errlog(ERROR, "%s: Parser error. Length was %llu "
                    "but can only be between 0 ... %s (pos: %d)",
                    __FUNCTION__, len, INT64_MAX, d->pos);
        return -1;
      }
      return tot;
    break;

    case 0x88 ... 0xff:
      errlog(ERROR, "%s: Parser error. Length was 0x%x "
                    "but can only be between 0x00 ... 0x87 (pos: %d)", 
                    __FUNCTION__, len, d->pos);
      return -1;
    break;

    // Cannot reach here.
    default:
      abort();
    break;
  }
}

/* Read a len, needed for REAL */
int64_t der_read_len(
    der_t *d)
{
  return get_len(d);
}


/* Basic tag fetcher */
bool der_next(
    der_t *d)
{
  uint8_t t;
  int64_t l;

  /* Never move onto a tag unless tag spot is clear */
  assert(d->tag == UINT8_MAX && d->len == -1);

  assert(d);
  t = der_getc(d);
  if (der_error(d))
    return false;

  l = get_len(d);
  if (l < 0)
    return false;

  d->tag = t;
  d->len = l;

  return true;
}

der_t * der_open_from_mem(
    unsigned char *buf,
    size_t len)
{
  der_t *d = NULL;
  struct der_mbuf *mb = NULL;

  if (!buf) {
    fprintf(stderr, "Error: Cannot use a null buffer\n");
    goto fin;
  }

  mb = calloc(1, sizeof(*mb));
  if (!mb)
    goto fin;
  mb->buf = buf;
  mb->len = len;
  mb->pos = 0;

  d = calloc(1, sizeof(*d));
  if (!d)
    goto fin;
  

  d->tag = -1;
  d->len = -1;

  /* Assign all the handlers */
  d->handle = mb;
  d->read = der_mbread;
  d->write = der_mbwrite;
  d->seek = der_mbseek;
  d->tell = der_mbtell;
  d->fileno = der_mbfileno;
  d->eof = der_mbeof;
  d->close = der_mbclose;
  d->error = der_mberror;

  return d;

fin:
  if (mb)
    free(mb);
  if (d)
    free(d);
  return NULL;
}

der_t * der_open_from_file(
    char *filename,
    const char *mode)
{
  FILE *f = NULL;
  der_t *d = NULL;

  f = fopen(filename, mode);
  if (!f) {
    fprintf(stderr, "Error: Cannot open filename: %s\n", strerror(errno));
    return NULL; 
  }

  /* allocate */
  d = calloc(1, sizeof(*d));
  if (!d)
    goto fin;

  d->tag = -1;
  d->len = -1;

  /* If this works, assign all the handlers */
  d->handle = f;
  d->read = der_fread;
  d->write = der_fwrite;
  d->seek = der_fseek;
  d->tell = der_ftell;
  d->fileno = der_ffileno;
  d->eof = der_feof;
  d->close = der_fclose;
  d->error = der_ferror;

  return d;

fin:
  if (f)
    fclose(f);
  if (d)
    free(d);
  return NULL;
}


void der_close(
    der_t *d)
{
  if (!d)
    return;

  if (d->handle) {
    if (d->close(d->handle) < 0)
    return;
  }

  if (d->err)
    free(d->err);
  free(d);

  return;
}



size_t der_read(
    void *buf,
    size_t sz,
    der_t *d)
{
  if (!d)
    return -1;

  if (d->read(buf, sz, 1, d->handle) != 1)
    if (d->eof(d->handle)) {
      D_ERRX(fin ,d, "Cannot read from stream: End of file.");
    }
    else {
      D_ERR(fin, d, "Cannot read from stream.");
    }

  d->pos += sz;
  return sz;

fin:
  return -1;
}



char der_getc(
    der_t *d)
{
  char buf = 0;

  if (!d)
    return 0;

  if (d->read(&buf, 1, 1, d->handle) != 1) {
    if (d->eof(d->handle)) {
      D_WARNX(d, "Cannot read from stream: End of file.");
    }
    else {
      D_WARN(d, "Cannot read from stream.");
    }
    return 0;
  }

  d->pos++;
  return buf;
}

int der_warning(
    der_t *d)
{
  if (!d)
    return 1;

  if (d->warn)
    return 1;

  return 0;
}


int der_error(
    der_t *d)
{
  if (!d)
    return 1;

  if (d->err)
    return 1;

  if (d->error(d->handle))
    return 1;

  return 0;
}


int der_seek(
    der_t *d,
    long pos,
    int wh)
{
  size_t off;
  if (!d)
    return -1;

  if (d->seek(d->handle, pos, wh) < 0) {
    D_WARN(d, "Could not seek to position");
    return -1;
  }
  d->pos = der_tell(d);

  return 0;
}

long der_tell(
    der_t *d)
{
  if (!d)
    return -1;

  if (d->tell(d->handle) < 0) {
    D_WARN(d, "Could not tell der position");
    return -1;
  }
}

bool der_parse_context(
    der_t *d,
    enum tag_class cl,
    uint8_t tag,
    bool implicit,
    int *clen)
{
  if (!d)
    return false;

  if (d->tag == UINT8_MAX && d->len == -1) {
    if (!der_next(d)) {
      D_ERRX(fin, d, "Unable to acquire next tag");
    }
  }

  if (D_CLASS(d) != cl || (d->tag & 0x1f) != tag)
    goto fin;

  if (implicit && D_CONS(d)) {
    D_ERRX(fin, d, "Implicit tag but a constructor");
  }

  *clen = d->len;

  der_cleartag(d);
  return true;

fin:
  return false;  
}

const char * der_errstr(
    der_t *d)
{
  return (const char *)d->err;
}

const char * der_warnstr(
    der_t *d)
{
  return (const char *)d->warn;
}
