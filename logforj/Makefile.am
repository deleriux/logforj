bin_PROGRAMS = logforj
logforj_SOURCES = logging.h \
                 main.c \
                 logging.c \
                 config.c \
                 nq.c \
                 heuristic.c \
                 worker.c \
                 nf.c \
                 nl.c \
                 standalone.c

noinst_HEADERS = logging.h \
                  nl.h \
                  nq.h \
                  nf.h \
                  heuristic.h \
                  worker.h \
                  standalone.h \
                  config.h
                 
logforj_CFLAGS = $(MNL_CFLAGS) $(NFTNL_CFLAGS) -I../der -Wall 
logforj_LDADD = $(MNL_LIBS) $(NFTNL_LIBS) ../der/libder.la
