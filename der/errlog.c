#include "common.h"
#include "errlog.h"

#include <pthread.h>
#include <stdarg.h>

static errlevel_t errlevel;
static pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;
static pthread_key_t errkey;
static pthread_once_t once = PTHREAD_ONCE_INIT;

struct loglist {
  char *buf;
  int lowest;
  errlog_t head;
};

static void clearlist(
    void *l)
{
  struct loglist *ll = l;
  errlog_t e, n;

  if (!ll)
    return;

  e = ll->head;
  while (e) {
    n = e->next;
    if (e->error)
      free(e->error);
    free(e);
    e = n;
  }
  free(ll);
}

static void createkey(
    void)
{
  pthread_key_create(&errkey, clearlist);
}

static struct loglist * getlog(
    void)
{
  pthread_once(&once, createkey);
  struct loglist *ll = pthread_getspecific(errkey);
  if (!ll) {
    ll = calloc(1, sizeof(struct loglist));
    if (!ll)
      abort();
    ll->lowest = INT_MAX;
    ll->buf = NULL;
    pthread_setspecific(errkey, ll);
  }
  return ll;
}

bool errlog_lessequal_level(
    errlevel_t level)
{
    struct loglist *ll = getlog();
    return ll->lowest < level ? true : false;
}

void errlog_set_level(
    errlevel_t level)
{
  pthread_rwlock_wrlock(&lock);
  errlevel = level;
  pthread_rwlock_unlock(&lock);
}

errlevel_t errlog_get_level(
    void)
{
  pthread_rwlock_rdlock(&lock);
  int level = errlevel;
  pthread_rwlock_unlock(&lock);
  return level;
}

void errlog(
    errlevel_t level,
    const char *fmt,
    ...)
{
  errlevel_t elevel;
  va_list ap;
  int rc;
  size_t sz = 0;
  char *buf = NULL;
  struct loglist *ll = getlog();
  errlog_t e = calloc(1, sizeof(struct errlog));
  errlog_t n;
  if (!e)
    abort();

  elevel = errlog_get_level();
  if (level >= elevel) {
    va_start(ap, fmt);
    sz = vsnprintf(buf, 0, fmt, ap);
    va_end(ap);

    sz += 1;
    buf = calloc(sz, 1);
    if (!buf) {
      abort();
    }

    va_start(ap, fmt);
    rc = vsnprintf(buf, sz, fmt, ap);
    va_end(ap);

    if (rc < 0) {
      free(buf);
      return;
    }

    e->score = level;
    e->error = buf;
    e->next = NULL;

    if (ll->lowest > level)
      ll->lowest = level;

    n = ll->head;
    if (!ll->head) {
      ll->head = e;
    }
    else {
      while (n->next)
        n = n->next;
      n->next = e;
    }
  }
  return;
}

void errlog_clear(
    void)
{
  struct loglist *ll = getlog();
  errlog_t e, n;

  if (!ll)
    return;

  e = ll->head;
  while (e) {
    n = e->next;
    if (e->error)
      free(e->error);
    free(e);
    e = n;
  }
  ll->head = NULL;
  return;
}


const char * errlog_print(
    errlevel_t level)
{
  struct loglist *ll = getlog();
  char *p = NULL;
  int total = 0;
  errlog_t e = ll->head;

  if (ll->buf) {
    free(ll->buf);
    ll->buf = NULL;
  }

  while (e) {
    if (e->score <= level) {
      total += snprintf(NULL, 0, "%03d: %s\n", e->score, e->error);
    }
    e = e->next;
  }
  total += 1;

  ll->buf = calloc(total, 1);
  if (!ll->buf)
    return "";

  p = ll->buf;
  e = ll->head;
  while (e) {
    if (e->score <= level) {
      p += snprintf(p, total-(p-ll->buf), "%03d: %s\n", e->score, e->error);
    }
    e = e->next;
  }

  return ll->buf;
}

