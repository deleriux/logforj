bin_PROGRAMS = logforj
logforj_SOURCES = logging.h \
                 nl.h \
                 main.c \
                 logging.c \
                 config.c \
                 nq.c \
                 heuristic.c \
                 worker.c \
                 nl.c

noinst_HEADERS = logging.h \
                  nl.h \
                  nq.h \
                  heuristic.h \
                  worker.h \
                  config.h
                 
logforj_CFLAGS = $(MNL_CFLAGS) -I../der -Wall 
logforj_LDADD = $(MNL_LIBS) ../der/libder.la
