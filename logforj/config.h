#ifndef _CONFIG_H_
#define _CONFIG_H_

void config_parse_args(int argc, char **argv);
uint32_t config_get_seen_mark(void);
uint32_t config_get_bad_mark(void);
uint16_t config_get_queue_id(void);
uint16_t config_get_queue_id(void);
int config_get_queue_len(void);
bool config_get_force(void);
bool config_get_standalone(void);
#endif
