
#
# configurable values
#

# config: postgres source tree
pg_top = $(HOME)/src/postgresql

# openssl/builtin algos (yes/no)
with_openssl = no

# enable/disable zlib (yes/no)
with_zlib = yes

#
# fixed values
#

SSL_PFX = /opt/apps/openssl

pgc = $(pg_top)/contrib/pgcrypto
CPPFLAGS = -I./compat -I./src -I$(pgc) -I$(SSL_PFX)/include
WEXTRA = -Wextra -Wno-unused-parameter -Wno-missing-field-initializers \
	 -Wmissing-prototypes -Wpointer-arith -Wendif-labels \
	 -Wdeclaration-after-statement -Wold-style-definition \
	 -Wstrict-prototypes -Wundef -Wformat -Wnonnull -Wstrict-overflow=1
CFLAGS = -g -O2 -Wall $(WEXTRA)
LDFLAGS = -g -L$(SSL_PFX)/lib
LIBS =
CC = gcc
LD = $(CC)
DEFS = 

ifeq ($(with_openssl),yes)
LIBS += -lcrypto -ldl
endif

ifeq ($(with_zlib),yes)
DEFS += -DHAVE_LIBZ
LIBS += -lz
endif

MY_SRC = src/upgp.c compat/postgres.c src/xparse.c \
	 src/randtest.c
BIN = upgp

PG_SRC = pgcrypto.c pgp-pgsql.c
USE_PGXS = 1
override PG_CONFIG = ./compat/pg_config
override PGXS = ./compat/pgxs.mk



all: $(BIN)

include $(pgc)/Makefile

UPGP_HDRS = $(wildcard src/*.h $(pgc)/*.h)
UPGP_SRCS = $(MY_SRC) $(addprefix $(pgc)/, $(filter-out $(PG_SRC), $(SRCS)))
UPGP_OBJS = $(addprefix obj/, $(notdir $(UPGP_SRCS:.c=.o)))

dbg:
	@echo UPGP_SRCS=$(UPGP_SRCS)
	@echo UPGP_OBJS=$(UPGP_OBJS)

obj/%.o: src/%.c $(UPGP_HDRS)
	@mkdir -p obj
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DEFS) -c $< -o $@

obj/%.o: compat/%.c $(UPGP_HDRS)
	@mkdir -p obj
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DEFS) -c $< -o $@

obj/%.o: $(pgc)/%.c $(UPGP_HDRS)
	@mkdir -p obj
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DEFS) -c $< -o $@

$(BIN): $(UPGP_OBJS)
	$(LD) $(LDFLAGS) -o $@ $(UPGP_OBJS) $(LIBS)

clean:
	rm -f obj/* $(BIN) core

tags: $(UPGP_HDRS) $(UPGP_SRCS)
	ctags $(UPGP_HDRS) $(UPGP_SRCS)

