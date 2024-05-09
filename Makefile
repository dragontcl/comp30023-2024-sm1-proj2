CC = gcc
CFLAGS = -Wall -g  # Include debugging symbols in all builds
DFLAGS = -DNDEBUG
SRC = main.c
OBJ = $(SRC:.c=.o)
EXE = fetchmail
DEBUG_EXE = fetchmail_debug

# Main production target
all: CFLAGS += $(DFLAGS)
all: $(EXE)

debug: $(DEBUG_EXE)

# The executable
$(EXE): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)
$(DEBUG_EXE): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)
# Object files
$(OBJ): $(SRC)
	$(CC) $(CFLAGS) -c $< -o $@
# Clean up artifacts
clean:
	rm -f $(OBJ) $(EXE) $(DEBUG_EXE)
cleanobj:
	rm -f $(OBJ)