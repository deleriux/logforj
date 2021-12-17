#include "common.h"
#include "nl.h"
#include "nq.h"
#include "logging.h"

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

/* Generic netfilter queue handlig module */

#define TCP_PROTO 6

static bool queue_bind(
    nq_t nq)
{
  struct nlmsghdr *hdr = NULL;
  struct nfgenmsg *msg = NULL;
  struct nfqnl_msg_config_cmd cmd = {0};
  struct nfqnl_msg_config_params mod = {0};

  /* Header */
  hdr = mnl_nlmsg_put_header(nl_buf_current(nq->nl));
  hdr->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG;
  hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  hdr->nlmsg_seq = nl_next_seqno(nq->nl);

  /* Netfilter payload */
  msg = mnl_nlmsg_put_extra_header(hdr, sizeof(struct nfgenmsg));
  msg->nfgen_family = NFPROTO_INET;
  msg->version = NFNETLINK_V0;
  msg->res_id = bswap_16(nq->group_id);

  /* Additional attributes */
  cmd.command = NFQNL_CFG_CMD_BIND;
  mod.copy_range = UINT16_MAX;
  mod.copy_mode = NFQNL_COPY_PACKET;

  mnl_attr_put(hdr, NFQA_CFG_CMD, sizeof(cmd), &cmd);
  mnl_attr_put(hdr, NFQA_CFG_PARAMS, sizeof(mod), &mod);
  mnl_attr_put_u32(hdr, NFQA_CFG_QUEUE_MAXLEN, bswap_32(nq->qmax));
  mnl_attr_put_u32(hdr, NFQA_CFG_FLAGS, bswap_32(NFQA_CFG_F_FAIL_OPEN));
  mnl_attr_put_u32(hdr, NFQA_CFG_MASK, bswap_32(NFQA_CFG_F_FAIL_OPEN));

  if (!nl_next_msg(nq->nl)) return false;
  if (nl_send(nq->nl) < 0) return false;
  if (nl_recv_ack(nq->nl, 1) < 0) return false;

  return true;
}


static inline nq_packets_t nq_packets_init(
    void)
{
  nq_packets_t nqps = NULL;
  nqps = malloc(sizeof(struct nq_packets));
  if (!nqps)
    return NULL;
  STAILQ_INIT(nqps);

  return nqps;
}

static inline bool parse_payload(
    nq_packet_t p)
{
  assert(p);
  struct iphdr *ip;
  struct ipv6hdr *ip6;
  struct tcphdr *tcp;

  /* l3 offset is always zero */
  p->l3_offset = 0;
  
  ip = (struct iphdr *)(&p->payload[p->l3_offset]);
  ip6 = (struct ipv6hdr *)(&p->payload[p->l3_offset]);
  if (ip->version == 4) {
    /* Packet is too truncated to process */
    if (p->payload_len < 20)
      return false;

    p->l3_protocol = AF_INET;
    p->l3_len = ip->ihl * sizeof(uint32_t);
    /* Must be at least 20 bytes */
    if (p->l3_len < 20)
      return false;

    /* Will only handle TCP packets */
    if (ip->protocol != TCP_PROTO)
      return false;

    memcpy(p->saddr.in4, &ip->saddr, 4);
    memcpy(p->daddr.in4, &ip->daddr, 4);
  }
  else if (ip->version == 6) {
    /* Packet is too truncated to process */
    if (p->payload_len < 40)
      return false;

    p->l3_protocol = AF_INET6;
    p->l3_len = 40;  /* for our purposes, always 40 bytes? */

    /* We dont handle extensions.. should fix this */
    if (ip6->nexthdr != TCP_PROTO)
      return false;

    memcpy(p->saddr.in6, &ip6->saddr, 16);
    memcpy(p->daddr.in6, &ip6->daddr, 16);
  }
  /* Do not parse non-ip headers */
  else
    return false;

  /* Packet is too truncated to process */
  if (p->l3_offset + p->l3_len + 20 > p->payload_len)
    return false;

  tcp = (struct tcphdr *)(&p->payload[p->l3_offset + p->l3_len]);
  p->l4_len = tcp->doff * sizeof(uint32_t);
  p->l4_offset = p->l3_offset + p->l3_len;
  p->sport = bswap_16(tcp->source);
  p->dport = bswap_16(tcp->dest);

  /* Packet is too truncated to process */
  if (p->l4_offset + p->l4_len > p->payload_len) 
    return false;

  p->l7_offset = p->l4_offset + p->l4_len;
  p->l7_len = p->payload_len - p->l7_offset;

  return true;
}

static inline bool packet_queue_append(
    nq_packet_t p,
    const struct nlmsghdr *hdr)
{
  struct nlattr *a;
  struct nfqnl_msg_packet_hdr *pkt_hdr;

  mnl_attr_for_each(a, hdr, sizeof(struct nfgenmsg)) {

    switch (mnl_attr_get_type(a)) {
      case NFQA_PAYLOAD:
        p->payload_len = mnl_attr_get_payload_len(a);
        p->payload = malloc(p->payload_len);
        if (!p->payload)
          return false;
        memcpy(p->payload, mnl_attr_get_payload(a), p->payload_len);
      break;

      case NFQA_CAP_LEN:
        if (mnl_attr_validate(a, MNL_TYPE_U32) < 0)
          goto fail;
        p->truncated = true;
      break;

      case NFQA_PACKET_HDR:
        if (mnl_attr_validate2(a, MNL_TYPE_UNSPEC,
            sizeof(struct nfqnl_msg_packet_hdr)) < 0)
          goto fail;
        pkt_hdr = mnl_attr_get_payload(a);
        p->packet_id = bswap_32(pkt_hdr->packet_id);
      break;

      default:
        continue;
      break;
    }
  }

  /* Packet in this case is too truncated to make it useful */
  if (p->payload_len < 40)
    goto fail;

  /* Get packet specific data */
  if (!parse_payload(p))
    p->truncated = true;

  return true;
fail:
  if (p->payload)
    free(p->payload);
  errno = EINVAL;
  return false;
}

static inline bool nq_packets_append(
    nq_packets_t pkts,
    const struct nlmsghdr *hdr)
{
  nq_packet_t p = NULL;

  if (!pkts || !hdr)
    return false;

  p = malloc(sizeof(struct nq_packet));
  if (!p) 
    return false;
  memset(p, 0, sizeof(struct nq_packet));

  /* Packets can be invalid, just dont add to queue */
  if (!packet_queue_append(p, hdr)) {
    free(p);
    return true;
  }

  STAILQ_INSERT_TAIL(pkts, p, next);
  return true;
}


nq_t nq_open(
    int group_id,
    int qmax,
    uint32_t seen,
    uint32_t bad)
{
  int yes = 1;

  if (!group_id || qmax < 0) {
    errno = EINVAL;
    return NULL;
  }

  nq_t nq = malloc(sizeof(struct nq));
  if (!nq)
    return NULL;

  nq->nl = nl_open(NETLINK_NETFILTER, 0, SOCK_CLOEXEC);
  if (!nq->nl)
    goto fail;

  /* this prevents getting ENOBUFS on overflow */
  if (setsockopt(nq->nl->fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &yes,
                 sizeof(yes)) < 0)
    goto fail;

  nq->qmax = qmax ? qmax : NQ_QMAX_DEFAULT;
  nq->group_id = group_id;
  nq->seen_mark = seen;
  nq->bad_mark = bad;

  if (!queue_bind(nq))
    goto fail;

  return nq;

fail:
  nq_close(nq);
  return NULL;
}


void nq_close(
    nq_t nq)
{
  if (!nq)
    return;

  if (nq->nl)
    nl_close(nq->nl);

  free(nq);
  return;
}



int nq_recv(
    nq_t nq, 
    nq_packets_t *pkts)
{
  int num = 0, rc;
  struct nlmsghdr *payload = NULL, *hdr;
  nq_packets_t ps = NULL;

  ps = nq_packets_init();
  if (!ps) {
    warn("nq_packets_init");
    goto fail;
  }

  if ((rc = nl_recv(nq->nl, &payload, &num)) < 0) {
    warn("nl_recv");
    goto fail;
  }

  hdr = payload;
  /* Iterate through packets received */
  while (mnl_nlmsg_ok(hdr, rc)) {
    if (!nq_packets_append(ps, hdr)) {
      warn("nq_packets_append");
      goto fail;
    }
    hdr = mnl_nlmsg_next(hdr, &rc);
  }

  free(payload);
  *pkts = ps;
  return num; 

fail:
  if (ps)
    nq_packets_free(ps);
  *pkts = NULL;
  free(payload);
  return -1;
}


void nq_packets_free(
    nq_packets_t pkts)
{
  nq_packet_t p, n;
  if (!pkts)
    return;

  p = STAILQ_FIRST(pkts);
  while (p) {
    n = STAILQ_NEXT(p, next);
    if (p->payload)
      free(p->payload);
    free(p);
    p = n;
  }

  free(pkts);
}


bool nq_verdict(
    nq_t nq,
    nq_packet_t p,
    int verdict)
{
  struct nlmsghdr *hdr = NULL;
  struct nfgenmsg *msg = NULL;
  struct nfqnl_msg_verdict_hdr vh = {0};
  struct nlattr *nest;

  hdr = mnl_nlmsg_put_header(nl_buf_current(nq->nl));
  hdr->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT;
  hdr->nlmsg_flags = NLM_F_REQUEST;
  hdr->nlmsg_seq = nl_next_seqno(nq->nl);

  // Netfilter payload
  msg = mnl_nlmsg_put_extra_header(hdr, sizeof(struct nfgenmsg));
  msg->nfgen_family = NFPROTO_INET;
  msg->version = NFNETLINK_V0;
  msg->res_id = bswap_16(nq->group_id);

  vh.verdict = verdict == NQ_UNDECIDED ? bswap_32(NF_ACCEPT) : bswap_32(NF_REPEAT);
  vh.id = bswap_32(p->packet_id);
  mnl_attr_put(hdr, NFQA_VERDICT_HDR, sizeof(vh), &vh);

  /* Add the conn mark indicating we've inspected this connection */
  if (verdict == NQ_GOOD || verdict == NQ_BAD) {
    nest = mnl_attr_nest_start(hdr, NFQA_CT);
    mnl_attr_put_u32(hdr, CTA_MARK, bswap_32(nq->seen_mark));
    mnl_attr_nest_end(hdr, nest);
  }

  /* Conditionally, add the mark to indicate the packet is bad */
  if (verdict == NQ_BAD)
    mnl_attr_put_u32(hdr, NFQA_MARK, bswap_32(nq->bad_mark));

  if (!nl_next_msg(nq->nl)) return false;
  if (nl_send(nq->nl) < 0) return false;

  /* If the verdict was bad. Log the packet */

  return true;
}


void nq_packet_log(
    nq_packet_t p, 
    const char *suffix)
{
  LOGSET("heuristics");

  char src[INET6_ADDRSTRLEN] = {0};
  char dst[INET6_ADDRSTRLEN] = {0};

  if (!p)
    return;

  inet_ntop(p->l3_protocol, &p->saddr.in4, src, INET6_ADDRSTRLEN);
  inet_ntop(p->l3_protocol, &p->daddr.in4, dst, INET6_ADDRSTRLEN);

  ELOG(WARNING, "Marked Suspicious packet: %s port %hu -> %s port %u : %s",
                src, p->sport, dst, p->dport, suffix);

}
