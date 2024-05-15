CC = gcc
CFLAGS = -Wall -g  # Include debugging symbols in all builds
DFLAGS = -DNDEBUG
OPENSSL_LIBS = -lssl -lcrypto  # Link against OpenSSL libraries
SRC = main.c
OBJ = $(SRC:.c=.o)
EXE = fetchmail
DEBUG_EXE = fetchmail_debug

# Main production target
all: CFLAGS += $(DFLAGS)
all: LDFLAGS += $(OPENSSL_LIBS)
all: $(EXE)

debug: LDFLAGS += $(OPENSSL_LIBS)
debug: $(DEBUG_EXE)


# The executable
$(EXE): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
$(DEBUG_EXE): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
# Object files
$(OBJ): $(SRC)
	$(CC) $(CFLAGS) -c $< -o $@
# Clean up artifacts
clean:
	rm -f $(OBJ) $(EXE) $(DEBUG_EXE)
cleanobj:
	rm -f $(OBJ)
