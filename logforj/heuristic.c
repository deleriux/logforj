#include "common.h"
#include "der.h"
#include "heuristic.h"

struct heuristic_state {
  char *buffer;
  bool last_check;
};

struct ldap_types {
  int id;
  const char *str;
};

static pthread_key_t key;

typedef bool (*check_heuristic)(unsigned char *p, size_t l);

static bool drop_ldap_heuristic(unsigned char *p, size_t l);
static bool drop_jrmp_heuristic(unsigned char *p, size_t l);

static const check_heuristic heuristics[] = {
  drop_ldap_heuristic,
  drop_jrmp_heuristic,
  NULL
};

static void destroy_data(
    void *data)
{
  struct heuristic_state *st = data;
  if (st) {
    if (st->buffer)
      free(st->buffer);
    free(st);
  }
}

static void __attribute__((constructor)) __heuristic_init(
    void)
{
  if (pthread_key_create(&key, destroy_data))
    err(EXIT_FAILURE, "Cannot initialize heuristic constructor");
}

static struct heuristic_state * get_state(
    void)
{
  struct heuristic_state *st = pthread_getspecific(key);
  if (!st) {
    st = malloc(sizeof(struct heuristic_state));
    if (!st) {
      warn("Failed setting heuristic state data. Bailing out");
      pthread_exit(NULL);
    }
    st->buffer = NULL;
    st->last_check = false;

    if (pthread_setspecific(key, st)) {
      warn("Failed setting heuristic state data. Bailing out"); 
      pthread_exit(NULL);
    }
  }

  return st;
}
    

static void set_error(
    bool match,
    const char *err)
{
  struct heuristic_state *st = get_state();
  if (st->buffer)
    free(st->buffer);
  st->buffer = strdup(err);
  if (!st->buffer) {
    warnx("Cannot set heuristic state buffer error message");
    pthread_exit(NULL);
  }
  st->last_check = match;
}


/* Unfortunately LDAP doens't announce its LDAP at all, instead the 
 * data is a anonymous BER encoded structure which just need to heuristically
 * ^guess^ to be a LDAP packet. Theres a chance we hit onto a false
 * positive as a lot of stuff is BER Encoded on the internet
 * however DER decoding this properly tries to reduce the cost at
 * the expense of CPU cycles */
static bool drop_ldap_heuristic(
    unsigned char *payload,
    size_t len)
{

  static const struct ldap_types ldap_message_ids[] = {
    { 23, "Start TLS request" }, /* Extended Operation (used for STARTTLS like negotiation) */
    { 0, "Bind request" },        /* LDAP Bind Request */
  };
#define LDAP_MESSAGES_MAX (sizeof(ldap_message_ids) / sizeof(int))

  der_t *der = NULL;
  char buf[64] = {0};
  int optlen;
  int slen;
  int64_t msgid = -1;

  /* Minimal LDAP Message consists of sequence, message ID and CHOICE
   * this is at least 8 bytes */
  if (len <= 8)
    return false;
 
  der = der_open_from_mem(payload, len);
  if (!der) {
    errx(EXIT_FAILURE, "Cannot open der from memory");
  }

  /* Format of LDAP Packet always includes sequence header at the start */
  if (!der_parse_sequence(der, &slen)) {
    set_error(false, "LDAP: Not a sequence");
    goto ok;
  }

  /* If it appears like a sequence but the length is wrong, its probably fine.. */
  if (slen >= len || slen <= 0) {
    set_error(false, "LDAP: Sequence tag found, but sequence length invalid");
    goto ok;
  }

  /* Message ID arrives next OK if not an integer */
  if (!der_parse_integer(der, &msgid)) {
    set_error(false, "LDAP: Message ID is not a valid integer");
    goto ok;
  }

  for (int i=0; i < LDAP_MESSAGES_MAX; i++) {
    if (der_parse_context(der, APPLICATION, ldap_message_ids[i].id, 
                          false, &optlen)) {
      snprintf(buf, 64, "LDAP: %s message type detected.", ldap_message_ids[i].str);
      set_error(true, buf);
      goto drop;
    }
  }

ok:
  der_close(der);
  set_error(false, "LDAP: No header detected");
  return false;

drop:
  der_close(der);
  return true;
}

/* Satisfyingly, this protocol contains a MAGIC value which is 
 * trivially easy to spot, so the heuristic is generally correct */
static bool drop_jrmp_heuristic(
    unsigned char *payload,
    size_t len)
{
  /* Must have enough payload to constitute a jrmp header */
  if (len < 7) {
    set_error(false, "JRMP: Message header too small");
    return false;
  }

  if (memcmp(payload, "JRMP" , 4) == 0) {
    set_error(true, "JRMP: Header detected");
    return true;
  }

  set_error(false, "JRMP: No header detected");
  return false;
}




bool heuristic_check(
    unsigned char *payload,
    size_t len)
{
  int n = 0;
  check_heuristic heur = heuristics[n++];
  while (heur) {
    if (heur(payload, len))
      return true;
    heur = heuristics[n++];
  }

  return false;
}


const char * heuristic_last_errstr(
    void)
{
  struct heuristic_state *st = get_state();
  return st->buffer;
}

bool heuristic_last_error(
    void)
{
  struct heuristic_state *st = get_state();
  return st->last_check;
}
