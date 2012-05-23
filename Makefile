CFLAGS = -O2 -g -Wall -W -D_FILE_OFFSET_BITS=64
OBJECTS = dwz.o hashtab.o
dwz: $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ -lelf
clean:
	rm -f $(OBJECTS) *~ core* dwz
