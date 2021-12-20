#ifndef _STANDALONE_H_
#define _STANDALONE_H_

#include "config.h"

#define STANDALONE_CHAIN_OUT "output"
#define STANDALONE_CHAIN_FWD "forward"
#define STANDALONE_CHAIN_PRI 5
#define STANDALONE_QUEUE_NUMBER (config_get_queue_id())
#define STANDALONE_BAD_MARK (config_get_bad_mark())
#define STANDALONE_SEEN_MARK (config_get_seen_mark())

void standalone_init(void);
void standalone_destroy(void);

#endif
