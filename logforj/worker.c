#include "common.h"
#include "nq.h"
#include "heuristic.h"
#include "worker.h"
#include "logging.h"

#define MAX_WORKERS 512

LOGSET("worker")

/* This is a transport struct */
struct worker_init_data {
  worker_config_t wc;
  int rc;
};


static pthread_t primary;
static pthread_key_t key;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static int worker_num = 0;
static worker_config_t workers[MAX_WORKERS] = {0};


static void * worker_run(void *data);


static void worker_config_destroy(
    void *data)
{
  worker_config_t wc = data;

  if (!wc)
    return;

  /* Remove from array */
  if (wc->id >= MAX_WORKERS || wc->id < 0) {
    ELOG(CRITICAL, "Invalid worker ID %d found whilst performing "
                   "destroy operation", wc->id);
    exit(EXIT_FAILURE);
  }

  workers[wc->id] = NULL;

  if (wc->nq)
    nq_close(wc->nq);
  free(wc);
}

static void __attribute__((constructor)) __init_worker(
    void)
{
  primary = pthread_self();
  if (pthread_key_create(&key, worker_config_destroy)) {
    ELOGERR(CRITICAL, "Cannot create worker thread-specific data");
    exit(EXIT_FAILURE);
  }
}

static bool worker_set_config(
    worker_config_t wc)
{
  worker_config_t old = pthread_getspecific(key);
  if (old) {
    errno = EEXIST;
    return false;
  }

  if (wc->id >= MAX_WORKERS || wc->id < 0) {
    errno = ERANGE;
    return false;
  }

  if (workers[wc->id] != NULL) {
    errno = EEXIST;
    return false;
  }

  if (pthread_setspecific(key, wc)) {
    return false;
  }

  /* Shouldn't need protecting with mutex .. */
  workers[wc->id] = wc;
  return true;
}

static void worker_notify_cancel(
    void *data)
{
  worker_config_t wc = data;
  if (!wc)
    return;

  ELOG(INFO, "Worker %d has been cancelled.", wc->id);
}

static void * worker_run(
    void *data)
{
  struct worker_init_data *wid = data;
  struct worker_config *wc = wid->wc;

  bool verdict;
  int rc;
  nq_packets_t pkts = NULL;
  nq_packet_t p;
  sigset_t all;

  if (!worker_set_config(wc)) {
    ELOG(CRITICAL, "Worker %d cannot configure thread-specific "
                   "data in worker.", wc->id);
    goto fail;
  }

  /* Dont respond to signals */
  sigfillset(&all);
  if (pthread_sigmask(SIG_BLOCK, &all, NULL)) {
    ELOG(CRITICAL, "Internal error. Worker %d cannot set signal mask", wc->id);
    goto fail;
  }

  ELOG(VERBOSE, "Worker %d has started listening on queue number %d", 
                wc->id, wc->qnum);

  /* At this point, we're in the main loop, signal peer thread we've started */
  pthread_mutex_lock(&lock);
  wid->rc = wc->id;
  pthread_mutex_unlock(&lock);
  pthread_cond_signal(&cond);

  pthread_cleanup_push(worker_notify_cancel, wc);
  while (1) {
    rc = nq_recv(wc->nq, &pkts);

    /* Manually control cancellation behaviour, since receiving a packet
     * and subsequently not marking it will lead to network loss */
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

    /* If a bad thing happens here, its probably best to exit */
    if (rc < 0) {
      ELOG(CRITICAL, "Worker %d exited due to failure receiving netlink "
                    "queue message", wc->id);
      exit(EXIT_FAILURE);
    }

    /* Loop through each packet */
    nq_foreach_packet(p, pkts) {

      /* A truncated packet contains no layer 7 data to inspect */
      if (nq_packet_is_truncated(p) || nq_packet_l7_len(p) == 0) {
        nq_verdict(wc->nq, p, NQ_UNDECIDED);
        continue;
      }

      verdict = heuristic_check(nq_packet_l7_payload(p), 
                                nq_packet_l7_len(p));

      nq_verdict(wc->nq, p, verdict ? NQ_BAD : NQ_GOOD);
      if (verdict) nq_packet_log(p, heuristic_last_errstr());}

    nq_packets_free(pkts);
    pkts = NULL;

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
  }
  pthread_cleanup_pop(0);

  return NULL;

fail:
  pthread_mutex_lock(&lock);
  wid->rc = -1;
  pthread_mutex_unlock(&lock);
  pthread_cond_signal(&cond);
  return NULL;
}


int worker_init(
    int qnum,
    int seen_markid,
    int bad_markid)
{
  struct worker_init_data wid = {0};
  worker_config_t wc = NULL;

  /* Setup config */
  wc = malloc(sizeof(struct worker_config));
  if (!wc)
    return -1;

  pthread_mutex_lock(&lock);
  wc->id = worker_num++;
  pthread_mutex_unlock(&lock);

  wc->qnum = qnum;
  wc->seen_markid = seen_markid;
  wc->bad_markid = bad_markid;
  wc->nq = nq_open(wc->qnum, SOCK_CLOEXEC, wc->seen_markid, wc->bad_markid);
  if (!wc->nq) {
    free(wc);
    return -1;
  }

  wid.rc = -2;
  wid.wc = wc;

  /* Spawn new thread */
  pthread_mutex_lock(&lock);
  if (pthread_create(&wc->thread, NULL, worker_run, &wid))
    return -1;

  /* Wait thread to start */
  while (wid.rc == -2) {
    pthread_cond_wait(&cond, &lock);
  }
  pthread_mutex_unlock(&lock);

  return wid.rc;
}

bool worker_cancel(
    int id)
{
  worker_config_t wc = NULL;
  pthread_t thread;

  if (id >= MAX_WORKERS || id < 0) {
    errno = ERANGE;
    return false;
  }

  wc = workers[id];
  if (!wc) {
    errno = ENOENT;
    return false;
  }

  thread = wc->thread;
  /* Send message to cancel worker */
  pthread_cancel(thread);

  /* Await cancellation */
  pthread_join(thread, NULL);
  return true;
}


worker_config_t worker_config(
    void)
{
  worker_config_t wc = pthread_getspecific(key);
  return wc;
}
