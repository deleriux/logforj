#ifndef _WORKER_H_
#define _WORKER_H_
#include "nq.h"

struct worker_config {
  int id;
  nq_t nq;
  int qnum;
  int seen_markid;
  int bad_markid;
  pthread_t thread;
};

typedef struct worker_config * worker_config_t;

bool worker_cancel(int id);
int worker_init(int qnum, int seen_markid, int bad_markid);

void worker_set_respawn(bool respawn);
worker_config_t worker_config(void);
#endif
