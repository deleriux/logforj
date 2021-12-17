#include "common.h"
#include "der.h"

static int oidnode(
    der_t *d,
    int *v)
{
  uint8_t byte;
  int res = 0;
  int c = 0;

  do {
    c++;
    byte = der_getc(d);
    if (der_error(d))
      return -1;
    res *= 128;
    res += (byte & 0x7f);
  } while (byte & 0x80);

  *v = res;
  return c;
}

static bool raw_read_number(
    der_t *d,
    int64_t len,
    bool sign,
    int64_t *out)
{
  int offset;
  uint8_t *buf = alloca(len);
  uint8_t target[8] = {0};
  if (!der_read(buf, len, d))
    goto fin;

  if (len > 8 || len <= 0)
    goto fin;

  *out = 0;
  offset = sizeof(int64_t) - len;
  memcpy((((uint8_t *)out)+offset), buf, len);
  *out = bswap_64(*out);
  
  return true;
fin:
  return false;
}

bool der_parse_integer(
    der_t *d,
    int64_t *out)
{
  int i;
  uint8_t *buf = NULL;
  bool neg = false;

  if (!d)
    return false;

  if (d->tag == UINT8_MAX && d->len == -1) {
    if (!der_next(d)) {
      D_ERRX(fin, d, "Unable to acquire next tag");
    }
  }

  if (D_CLASS(d) != UNIVERSAL || D_TAG(d) != INTEGER || D_CONS(d))
    goto fin;

  /* Integer cannot be 0 or less in length, and we dont support over 64 bits */
  if (d->len <= 0 || d->len > 8)
    goto fin;

  if (!raw_read_number(d, d->len, true, out))
    goto fin;

  der_cleartag(d);
  return true;

fin:
  return false;
}


bool der_parse_sequence(
    der_t *d,
    int *slen)
{
  if (!d)
    return false;

  if (d->tag == UINT8_MAX && d->len == -1) {
    if (!der_next(d)) {
      D_ERRX(fin, d, "Unable to acquire next tag");
    }
  }

  if (D_CLASS(d) != UNIVERSAL || D_TAG(d) != SEQUENCE || !D_CONS(d))
    goto fin;

  *slen = d->len;

  der_cleartag(d);
  return true;

fin:
  return false;
}


bool der_parse_oid(
    der_t *d,
    char **out)
{
  int last, rc, sz, oididx=2, id, i;
  int nodes[512];
  char oidbuf[1024], *p;
  memset(nodes, 0, sizeof(nodes));

  if (!d)
    return false;

  if (d->tag == UINT8_MAX && d->len == -1) {
    if (!der_next(d)) {
      D_ERRX(fin, d, "Unable to acquire next tag");
    }
  }

  if (D_CLASS(d) != UNIVERSAL || D_TAG(d) != OID || D_CONS(d))
    goto fin;

  if (d->len <= 0) {
    D_ERRX(fin, d, "OID tag cannot be 0 or lower in length");
  }

  /* Perform the first 2 elements logic */
  last = d->len;
  sz = oidnode(d, &id);
  if (sz > last || sz < 0) {
    D_ERRX(fin, d, "OID Exceeded byte boundary");
  }

  if (id < 80) {
    nodes[0] = id / 40;
    nodes[1] = id % 40;
  }
  else {
    nodes[0] = 2;
    nodes[1] = id - 80;
  }

  /* Iterate through the rest of the OIDs.. */
  while (sz < last) {
    if ((rc = oidnode(d, &id)) < 0) {
      D_ERRX(fin, d, "OID Exceeded byte boundary");
    }
    
    sz +=rc;
    nodes[oididx++] = id;
    if (oididx > 511) {
      D_ERRX(fin, d, "OID index exceeded. Probably bad OID");
    }
  }
  if (sz > last) {
    D_ERRX(fin, d, "OID Exceeded byte boundary");
  }

  /* Convert the OID nodes into a buffer */
  memset(oidbuf, 0, sizeof(oidbuf));
  p = oidbuf;
  for (i=0; i < oididx-1; i++)
    p += snprintf(p, 512-(p-oidbuf), "%d.", nodes[i]);
  p += snprintf(p, 512-(p-oidbuf), "%d", nodes[i]);

  *out = strdup(oidbuf);

  der_cleartag(d);
  return true;

fin:
  return false;
}
