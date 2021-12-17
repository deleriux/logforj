#include "common.h"
#include "logging.h"
#include "worker.h"
#include "config.h"

#define MODULES_PATH "/sys/module"

LOGSET("logforj")

static volatile bool running = true;

static void finish(
    void)
{
  for (int i=0; i < config_get_queue_len(); i++) {
    worker_cancel(i);
  }
  ELOG(ERROR, "logforj has exited");
}

static void module_check(
    void)
{
  int fd = -1;
  static const char *modname = "nf_conntrack_netlink";
  char path[1024] = {0};

  if (config_get_force())
    return;

  snprintf(path, 1023, "%s/%s", MODULES_PATH, modname);
  fd = open(path, O_DIRECTORY|O_RDONLY);
  if (fd < 0) {
    ELOG(CRITICAL, "Cannot find kernel module loaded %s, which is required "
         "to run this program. Exiting", modname);
    ELOG(CRITICAL, "If you know this module is loaded. Pass --force to skip "
          "this check.");
    exit(EXIT_FAILURE);
  }
  close(fd);
}

int main(
    int argc,
    char **argv)
{
  sigset_t sigs;
  int rc;
  int signum;

  config_parse_args(argc, argv);

  ELOG(INFO, "Starting logforj");

  module_check();

  for (int i=config_get_queue_id(); 
           i < config_get_queue_id()+config_get_queue_len(); 
           i++) {
    /* Meat of all work is done in workers */
    if ((rc = worker_init(i, config_get_seen_mark(),
                             config_get_bad_mark())) < 0) {
      ELOG(CRITICAL, "Cannot initiailze worker");
      exit(EXIT_FAILURE);
    }
  }

  atexit(finish);

  sigemptyset(&sigs);
  sigaddset(&sigs, SIGINT);
  sigaddset(&sigs, SIGTERM);
  sigprocmask(SIG_BLOCK, &sigs, NULL);

  /* Begin loop */
  while (running) {
    sigwait(&sigs, &signum);
    switch (signum) {
      case SIGINT:
      case SIGTERM:
        ELOG(ERROR, "Received signal to finish");
        running = false;
      break;

      default:
        ELOG(CRITICAL, "Received unhandled, but pending signal");
        running = false;
      break;
    }
  }

  exit(EXIT_SUCCESS);
}
