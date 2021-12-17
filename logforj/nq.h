#ifndef _NQ_H_
#define _NQ_H_
#include "nl.h"
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>

#define NQ_QMAX_DEFAULT 128
#define NQ_LOG_TIMEOUT 10

#define NQ_GOOD 0
#define NQ_BAD 1
#define NQ_UNDECIDED 2

struct nq {
  nl_t nl;
  uint32_t seen_mark;
  uint32_t bad_mark;
  int group_id;
  int qmax;
};

struct nq_packet {
  /* Required for returning verdict */
  uint32_t packet_id;

  /* Indicates if the packet was truncated to us */
  bool truncated;

  /* The three protocols */
  int l3_protocol; /* type (AF_INET/AF_INET6) */
  off_t l3_offset; /* where it starts in the payload */
  size_t l3_len;   /* size of the packet */

  int l4_protocol; /* type (TCP/UDP) */
  off_t l4_offset; /* where it starts in the payload */
  size_t l4_len;   /* size of the packet */

  off_t l7_offset; /* where it starts in the payload */
  size_t l7_len;   /* size of the packet */

  /* Layer 3 address */
  union {
    uint8_t in4[4];
    uint8_t in6[16];
  } saddr;
  union {
    uint8_t in4[4];
    uint8_t in6[16];
    void *ptr;
  } daddr;

  /* Layer 4 ports */
  uint16_t sport;
  uint16_t dport;

  /* Payload */
  uint8_t *payload;

  /* Total size of payload (truncated flag above indicates if not all packet) */
  size_t payload_len;

  STAILQ_ENTRY(nq_packet) next;
};

STAILQ_HEAD(nq_packets, nq_packet);

typedef struct nq * nq_t;
typedef struct nq_packet * nq_packet_t;
typedef struct nq_packets * nq_packets_t;

int nq_recv(nq_t nq, nq_packets_t *pkts);
nq_t nq_open(int group_id, int qmax, uint32_t seen_mark, uint32_t bad_mark);
void nq_close(nq_t nq);

void nq_packets_free(nq_packets_t pkts);
bool nq_verdict(nq_t nq, nq_packet_t p, int verdict);
void nq_packet_log(nq_packet_t p, const char *suffix);

static inline unsigned char * nq_packet_l7_payload(
    nq_packet_t p)
{
  return (unsigned char *)(&p->payload[p->l7_offset]);
}

static inline size_t nq_packet_l7_len(
    nq_packet_t p)
{
  return p->l7_len;
}

static inline bool nq_packet_is_truncated(
    nq_packet_t p)
{
  return p->truncated;
}

void nq_log_packet(
    nq_packet_t p,
    const char *suffix);

#define nq_foreach_packet(p, pkts) STAILQ_FOREACH(p, pkts, next)

#endif
