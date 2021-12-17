#ifndef _ERRLOG_H
#define _ERRLOG_H

#define ERRLOG_DEBUG3    800
#define ERRLOG_DEBUG2    400
#define ERRLOG_DEBUG     200
#define ERRLOG_VERBOSE    50
#define ERRLOG_INFO       20
#define ERRLOG_WARNING    10
#define ERRLOG_ERROR       0
#define ERRLOG_CRITICAL -100

enum errlevel {
  FATAL   = ERRLOG_CRITICAL,
  ERROR   = ERRLOG_ERROR,
  WARNING = ERRLOG_WARNING,
  INFO    = ERRLOG_INFO,
  VERBOSE = ERRLOG_VERBOSE,
  DEBUG   = ERRLOG_DEBUG,
  DEBUG2  = ERRLOG_DEBUG2,
  DEBUG3  = ERRLOG_DEBUG3
};

struct errlog {
  char *error;
  int score;

  struct errlog *next;
};

typedef struct errlog * errlog_t;
typedef enum errlevel errlevel_t;


errlevel_t errlog_get_level(void);
bool errlog_lessequal_level(errlevel_t level);
void errlog_set_level(errlevel_t level);
void errlog(errlevel_t level, const char *fmt, ...);
void errlog_clear(void);
const char * errlog_print(errlevel_t level);

static inline bool errlog_warning(void) { return errlog_lessequal_level(WARNING); }
static inline bool errlog_error(void) { return errlog_lessequal_level(ERROR); }
static inline const char * errlog_str_warnings(void) { return errlog_print(WARNING); }
static inline const char * errlog_str_errors(void) { return errlog_print(ERROR); }

#undef ERRLOG_DEBUG3
#undef ERRLOG_DEBUG2
#undef ERRLOG_DEBUG
#undef ERRLOG_VERBOSE
#undef ERRLOG_INFO
#undef ERRLOG_WARNING
#undef ERRLOG_ERROR
#undef ERRLOG_CRITICAL

#endif
