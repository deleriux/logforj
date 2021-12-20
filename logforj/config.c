#include "common.h"
#include "logging.h"
#include "config.h"
#include <getopt.h>

LOGSET("config")

#define PROGNAME "logforj"

struct config {
  uint32_t seen_mark;
  uint32_t bad_mark;
  uint16_t queue_id;
  int queue_len;
  const char *logfile;
  bool verbose;
  bool force;
  bool standalone;
} config;

static inline void print_usage(
    void)
{
  printf("Usage: %s [OPTIONS]\n", PROGNAME);
}

static inline void print_help(
    void)
{ 
  printf(
"Block Log4j/Log4Shell attacks by matching LDAP traffic and JRMP session traffic.\n\n"
"OPTIONS\n"
"    --help                -h          Print this help\n"
"    --log-file            -l LOGFILE  Log to file (default: stdout).\n"
"    --seen-mark           -m MARK     Netfilter mark to use on checked connections (default: 9)\n"
"    --bad-mark            -b MARK     Netfilter mark to use on matched Log4j connections (default: 10)\n"
"    --queue               -q ID       Netfilter queue-id to attach to (default: 10)\n"
"    --queue-size          -s LEN      Netfilter queue-id to attach to (default: 1)\n"
"    --force,              -f          Skip some sanity checks on startup (default: false)\n"
"    --verbose             -v          Verbose logging (default: false)\n"
"\n"
"\n");
}

void config_parse_args(
    int argc, 
    char **argv)
{
  int lf = -1;
  char c;
  int val; 
  int optidx;
  int ncpus = sysconf(_SC_NPROCESSORS_ONLN);

  /* Set config defaults */
  config.logfile = "stdout";
  config.seen_mark = 9;
  config.bad_mark = 10;
  config.queue_id = 10;
  config.queue_len = 1;
  config.verbose = false;
  config.force = false;
  config.standalone = true;

  static struct option long_options[] = {
    { "help",        no_argument,       NULL, 'h' },
    { "log-file",    required_argument, NULL, 'l' },
    { "seen-mark",   required_argument, NULL, 'm' },
    { "bad-mark",    required_argument, NULL, 'b' },
    { "queue",       required_argument, NULL, 'q' },
    { "queue-size",  required_argument, NULL, 's' },
    { "verbose",     no_argument,       NULL, 'v' },
    { "force",       no_argument,       NULL, 'f' },
    {  0,            0,                 0,     0  },
  };

  while (1) {
    c = getopt_long(argc, argv, "fvhl:m:b:q:s:", long_options, &optidx);
    if (c == -1)
      break;

    switch(c) {
      case 'l':
        /* Open in append mode logfile */
        config.logfile = strdup(optarg);
        if (!config.logfile) {
          ELOGERR(CRITICAL, "Cannot set log file %s", optarg);
          exit(EXIT_FAILURE);
        }
        lf = open(optarg, O_WRONLY|O_APPEND|O_CREAT, 0666);
        if (lf < 0) {
          ELOGERR(CRITICAL, "Cannot set log file %s", optarg);
          exit(EXIT_FAILURE);
        }
      break;

      case 'v':
        config.verbose = true;
      break;

      case 'f':
        config.force = true;
      break;

      case 'm':
        val = atoi(optarg);
        if (val <= 0 || val > UINT32_MAX) {
          ELOG(CRITICAL, "Config error. Seen mark must be between %d and %d",
               1, UINT32_MAX);
        }
        config.seen_mark = (uint32_t)val;
        config.standalone = false;
      break;

      case 'b':
        val = atoi(optarg);
        if (val <= 0 || val > UINT32_MAX) {
          ELOG(CRITICAL, "Config error. Bad mark must be between %d and %d",
               1, UINT32_MAX);
        }
        config.bad_mark = (uint32_t)val;
        config.standalone = false;
      break;

      case 'q':
        val = atoi(optarg);
        if (val <= 0 || val > UINT16_MAX) {
          ELOG(CRITICAL, "Config error. Queue ID must be between %d and %d",
               1, UINT16_MAX);
        }
        config.queue_id = (uint16_t)val;
        config.standalone = false;
      break;

      case 's':
        val = atoi(optarg);
        if (val <= 0 || val > ncpus) {
          ELOG(CRITICAL, "Config error. Queue ID must be between %d and %d",
               1, ncpus);
        }
        config.queue_len = val;
        config.standalone = false;
      break;
  
      case 'h':
        print_usage();
        print_help();
        exit(1);
      break;
  
      default:
        print_usage();
        print_help();
        exit(1);
      break;
    }
  }

  /* Post checks */
  if (config.bad_mark == config.seen_mark) {
    ELOG(CRITICAL, "Config error. Seen mark and bad mark cannot be equal");
    exit(EXIT_FAILURE);
  }

  if (((int)config.queue_id + config.queue_len) > UINT16_MAX) {
    ELOG(CRITICAL, "The maximum queue ID must not exceed %d", UINT16_MAX);
    exit(EXIT_FAILURE);
  }

  /* Apply log file changes */
  if (config.standalone)
    ELOG(WARNING, "Starting %s in standalone mode", PROGNAME);
  else
    ELOG(WARNING, "Starting %s --seen-mark=%d --bad-mark=%d --queue=%d --queue-size=%d",
                PROGNAME, config.seen_mark, config.bad_mark, config.queue_id, config.queue_len);

  if (strcmp(config.logfile, "stdout") != 0) {
    ELOG(WARNING, "Switching to logfile %s", config.logfile);

    fflush(stdout);
    if (dup2(lf, STDOUT_FILENO) < 0) {
      ELOGERR(CRITICAL, "Cannot set log file %s", optarg);
      exit(EXIT_FAILURE);
    }

    /* Correctly configure line buffering semantics */
    setlinebuf(stdout);
    close(lf);

    ELOG(INFO, "Switched to logfile %s", config.logfile);
  }

  if (config.verbose)
    log_setlevel(VERBOSE);
}


uint16_t config_get_queue_id(
    void)
{
  return config.queue_id;
}

int config_get_queue_len(
    void)
{
  return config.queue_len;
}

uint32_t config_get_bad_mark(
    void)
{
  return config.bad_mark;
}

uint32_t config_get_seen_mark(
    void)
{
  return config.seen_mark;
}

bool config_get_force(
    void)
{
  return config.force;
}

bool config_get_standalone(
    void)
{
  return config.standalone;
}
