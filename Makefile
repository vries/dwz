CFLAGS = -O2 -g -Wall -W
OBJECTS = dwz.o hashtab.o sha1.o
dwz: $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ -lelf
clean:
	rm -f $(OBJECTS) *~ core* dwz
