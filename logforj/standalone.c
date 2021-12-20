#include "common.h"
#include "nf.h"
#include "standalone.h"
#include "logging.h"

#include <ifaddrs.h>

LOGSET("standalone")

static char * standalone_get_default_interface(
    void)
{
  /* Create an outbound connection over UDP to 8.8.8.8 */
  struct ifaddrs *addrs = NULL, *ad;
  int fd = -1;
  socklen_t slen = sizeof(struct sockaddr_in);
  struct sockaddr_in in = {0};
  char *ifa = NULL;

  in.sin_family = AF_INET;

  inet_pton(AF_INET, "8.8.8.8", &in.sin_addr);
  fd = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, 0);
  if (fd < 0)
    return NULL;

  if (connect(fd, (struct sockaddr *)&in, sizeof(struct sockaddr_in)) < 0)
    goto fail;

  /* Return the source address */
  if (getsockname(fd, &in, &slen) < 0)
    goto fail;

  if (getifaddrs(&addrs) < 0)
    goto fail;

  ad = addrs;
  /* Seach a list of interfaces for our matching bound IP */
  while (ad) {
    struct sockaddr_in *tmp = (struct sockaddr_in *)ad->ifa_addr;
    if (ad->ifa_addr->sa_family == AF_INET) {
      if (memcmp(&tmp->sin_addr, &in.sin_addr, 4) == 0) {
        ifa = strdup(ad->ifa_name);
        goto end;
      }
    }
    ad = ad->ifa_next;
  }

fail:
  ELOGERR(CRITICAL, "Cannot fetch default route");
end:
  if (fd > -1)
    close(fd);
  if (addrs)
    freeifaddrs(addrs);
  return ifa;
}





static bool standalone_flush(
    nf_t nf)
{
  if (!nf) {
    errno = EINVAL;
    return false;
  }

  if (!nf_txn_begin(nf)) {
    ELOGERR(CRITICAL, "Cannot start netfilter transaction");
    return false;
  }

  if (!nf_table_delete(nf, "inet", "logforj")) {
    ELOGERR(CRITICAL, "Cannot create deletion request");
    return false;
  }

  if (!nf_txn_commit(nf)) {
    ELOGERR(CRITICAL, "Cannot commit netfilter transaction");
    return false;
  }

  if (!nf_transact(nf)) {
    if (errno != ENOENT) {
      ELOGERR(CRITICAL, "Cannot flush logforj table");
      return false;
    }
  }
  return true;
}

static bool standalone_add_queue_rule(
    nf_t nf,
    struct nftnl_chain *cha)
{
  char *ifa = standalone_get_default_interface();
  struct nftnl_rule *rul = NULL;
  struct nftnl_expr *exp = NULL;

  if (!ifa)
    goto fail;

  rul = nf_rule_init(nf, cha, "queuer");
  /* oifname xxx */
  exp = nftnl_expr_alloc("meta");
  if (!exp)
    goto fail;

  nftnl_expr_set_u32(exp, NFTNL_EXPR_META_KEY, NFT_META_OIFNAME);
  nftnl_expr_set_u32(exp, NFTNL_EXPR_META_DREG, NFT_REG_1);
  nftnl_rule_add_expr(rul, exp);

  exp = nftnl_expr_alloc("cmp");
  if (!exp)
    goto fail;

  nftnl_expr_set_u32(exp, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
  nftnl_expr_set_u32(exp, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
  nftnl_expr_set_str(exp, NFTNL_EXPR_CMP_DATA, ifa);
  nftnl_rule_add_expr(rul, exp);

  exp = nftnl_expr_alloc("meta");
  if (!exp)
    goto fail;

  /* l4proto tcp */
  nftnl_expr_set_u32(exp, NFTNL_EXPR_META_KEY, NFT_META_L4PROTO);
  nftnl_expr_set_u32(exp, NFTNL_EXPR_META_DREG, NFT_REG_1);
  nftnl_rule_add_expr(rul, exp);

  exp = nftnl_expr_alloc("cmp");
  if (!exp)
    goto fail;

  nftnl_expr_set_u32(exp, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
  nftnl_expr_set_u32(exp, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
  nftnl_expr_set_u32(exp, NFTNL_EXPR_CMP_DATA, 6 /* tcp */);
  nftnl_rule_add_expr(rul, exp);

  /* ct mark != 9 */
  exp = nftnl_expr_alloc("ct");
  if (!exp)
    goto fail;

  nftnl_expr_set_u32(exp, NFTNL_EXPR_CT_KEY, NFT_CT_MARK);
  nftnl_expr_set_u32(exp, NFTNL_EXPR_CT_DREG, NFT_REG_1);
  nftnl_rule_add_expr(rul, exp);

  exp = nftnl_expr_alloc("cmp");
  if (!exp)
    goto fail;

  nftnl_expr_set_u32(exp, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
  nftnl_expr_set_u32(exp, NFTNL_EXPR_CMP_OP, NFT_CMP_NEQ);
  nftnl_expr_set_u32(exp, NFTNL_EXPR_CMP_DATA, STANDALONE_SEEN_MARK);
  nftnl_rule_add_expr(rul, exp);

  /* ct state established */
  exp = nftnl_expr_alloc("ct");
  if (!exp)
    goto fail;

  nftnl_expr_set_u32(exp, NFTNL_EXPR_CT_KEY, NFT_CT_STATE);
  nftnl_expr_set_u32(exp, NFTNL_EXPR_CT_DREG, NFT_REG_1);
  nftnl_rule_add_expr(rul, exp);

  exp = nftnl_expr_alloc("bitwise");
  if (!exp)
    goto fail;

  nftnl_expr_set_u32(exp, NFTNL_EXPR_BITWISE_SREG, NFT_REG_1);
  nftnl_expr_set_u32(exp, NFTNL_EXPR_BITWISE_LEN, 4);
  nftnl_expr_set_u32(exp, NFTNL_EXPR_BITWISE_MASK, NF_CT_STATE_BIT(IP_CT_ESTABLISHED));
  nftnl_expr_set_u32(exp, NFTNL_EXPR_BITWISE_XOR, 0);
  nftnl_expr_set_u32(exp, NFTNL_EXPR_BITWISE_DREG, NFT_REG_1);
  nftnl_rule_add_expr(rul, exp);

  exp = nftnl_expr_alloc("cmp");
  if (!exp)
    goto fail;

  nftnl_expr_set_u32(exp, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
  nftnl_expr_set_u32(exp, NFTNL_EXPR_CMP_OP, NFT_CMP_NEQ);
  nftnl_expr_set_u32(exp, NFTNL_EXPR_CMP_DATA, 0);
  nftnl_rule_add_expr(rul, exp);

  if (!nf_rule_add_queue(rul, STANDALONE_QUEUE_NUMBER, 1, 
                         NFT_QUEUE_FLAG_BYPASS|NFT_QUEUE_FLAG_CPU_FANOUT))
    goto fail;

 // queue num 10-13 bypass fanout
  if (!nf_rule_create(nf, rul))
    goto fail;

  free(ifa);
  nftnl_rule_free(rul);
  return true;

fail:
  ELOG(CRITICAL, "Cannot set queueing rule");
  if (!ifa)
    free(ifa);
  if (exp)
    nftnl_expr_free(exp);
  if (rul)
    nftnl_rule_free(rul);

  return false;
}

static bool standalone_add_reset_rule(
    nf_t nf,
    struct nftnl_chain *cha)
{
  struct nftnl_rule *rst = NULL;
  struct nftnl_expr *exp = NULL;
  if (!nf || !cha) {
    ELOGERR(CRITICAL, "Invalid chain");
    return false;
  }

  rst = nf_rule_init(nf, cha, "resetter");
  if (!rst) {
    ELOGERR(CRITICAL, "Cannot allocate log rule");
    return false;
  }

  if (!nf_rule_add_mark(rst, STANDALONE_BAD_MARK)) {
    ELOGERR(CRITICAL, "Cannot set mark on reset rule");
    return false;
  }

  exp = nftnl_expr_alloc("cmp");
  if (!exp) {
    ELOGERR(CRITICAL, "Cannot allocate log rule");
    return false;
  }
  nftnl_expr_set_u32(exp, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
  nftnl_expr_set_u32(exp, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
  nftnl_expr_set_u32(exp, NFTNL_EXPR_CMP_DATA, STANDALONE_BAD_MARK);
  nftnl_rule_add_expr(rst, exp);

  /* counter */
  exp = nftnl_expr_alloc("counter");
  if (!exp) {
    ELOGERR(CRITICAL, "Cannot allocate log rule");
    return false;
  }
  nftnl_rule_add_expr(rst, exp);

  /* reject with tcp reset */
  exp = nftnl_expr_alloc("reject");
  nftnl_expr_set_u32(exp, NFTNL_EXPR_REJECT_TYPE, NFT_REJECT_TCP_RST);
  nftnl_expr_set_u32(exp, NFTNL_EXPR_REJECT_CODE, 0);
  nftnl_rule_add_expr(rst, exp);

  if (!nf_rule_create(nf, rst)) {
    ELOGERR(CRITICAL, "Cannot allocate log rule");
    return false;
  }

  ELOG(VERBOSE, "Created reset rule");

  nftnl_rule_free(rst);
  return true;
}

bool standalone_create_logforj_table(
    nf_t nf)
{
  struct nftnl_table *tbl = NULL;
  struct nftnl_chain *out, *fwd;

  if (!nf) {
    errno = EINVAL;
    return false;
  }

  if (!nf_txn_begin(nf)) {
    ELOGERR(CRITICAL, "Cannot start netfilter transaction creating table");
    return false;
  }

  tbl = nf_table_create(nf, "inet", "logforj");
  if (!tbl) {
    ELOGERR(CRITICAL, "Cannot create logforj table");
    return false;
  }
  ELOG(VERBOSE, "Created logforj table");

  /* Create chains */
  fwd = nf_chain_create(nf, tbl, STANDALONE_CHAIN_FWD,
                        "forward", "filter", STANDALONE_CHAIN_PRI, "accept");
  out = nf_chain_create(nf, tbl, STANDALONE_CHAIN_OUT,
                        "out", "filter", STANDALONE_CHAIN_PRI, "accept");

  if (!fwd || !out) {
    ELOGERR(CRITICAL, "Cannot create logforj chains");
    return false;
  }
  ELOG(VERBOSE, "Created logforj chains");

  if (!standalone_add_reset_rule(nf, fwd))
    ELOG(CRITICAL, "Cannot create reset rule");

  if (!standalone_add_reset_rule(nf, out))
    ELOG(CRITICAL, "Cannot create reset rule");

  if (!standalone_add_queue_rule(nf, fwd))
    ELOG(CRITICAL, "Cannot create queue rule");

  if (!standalone_add_queue_rule(nf, out))
    ELOG(CRITICAL, "Cannot create queue rule");

  if (!nf_txn_commit(nf)) {
    ELOGERR(CRITICAL, "Cannot commit netfilter transaction creating table");
    return false;
  }

  if (!nf_transact(nf)) {
    ELOGERR(CRITICAL, "Cannot initialize logforj table");
    return false;
  }

  /* Free stuff here */
  nftnl_chain_free(out);
  nftnl_chain_free(fwd);
  nftnl_table_free(tbl);
  return true;
}


void standalone_init(
    void)
{
  nf_t nf = nf_open(0, SOCK_CLOEXEC);
  if (!nf) {
    ELOG(CRITICAL, "Cannot open netfilter connection");
    exit(EXIT_FAILURE);
  }

  /* Flush an old table, if one exists */
  if (!standalone_flush(nf))
    exit(EXIT_FAILURE);

  /* Create the tables */
  if (!standalone_create_logforj_table(nf))
    exit(EXIT_FAILURE);


  nf_close(nf);
}

void standalone_destroy(
    void)
{
  nf_t nf = nf_open(0, SOCK_CLOEXEC);
  if (!nf) {
    ELOG(CRITICAL, "Cannot open netfilter connection");
    exit(EXIT_FAILURE);
  }

  /* Flush an old table, if one exists */
  if (!standalone_flush(nf))
    exit(EXIT_FAILURE);

  nf_close(nf);
  return;
}
