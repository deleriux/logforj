#include "common.h"
#include "nf.h"
#include "logging.h"

LOGSET("standalone")


bool standalone_flush(
    nf_t nf)
{
  nf_t nf = nf_open(0, SOCK_CLOEXEC);
  if (!nf) {
    ELOG(CRITICAL, "Cannot open netfilter connection");
    return false;
  }

  if (!nf_txn_begin(nf)) {
    ELOG(CRITICAL, "Cannot start netfilter transaction");
    return false;
  }

  if (!nf_table_delete(nf, "inet", "logforj")) {
    ELOG(CRITICAL, "Cannot create deletion request");
    return false;
  }

  if (!nf_txn_commit(nf)) {
    ELOG(CRITICAL, "Cannot commit netfilter transaction");
    return false;
  }

  if (!nf_transact(nf)) {
    if (errno != ENOENT) {
      ELOG(CRITICAL, "Cannot flush logforj table");
      return false;
    }
  }
  return true;
}

void standalone_destroy(
    void)
{
  return;
}
