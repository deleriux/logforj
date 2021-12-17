#ifndef _HEURISTIC_H_
#define _HEURISTIC_H_

bool heuristic_check(unsigned char *l7_payload, size_t l7_len);
const char * heuristic_last_errstr(void);
bool heuristic_last_error(void);
#endif
