
CFLAGS := -O2 -g -Wall

all: rfc4880dump verify

DUMP_OBJS := rfc4880dump.o
rfc4880dump: $(DUMP_OBJS)
	$(CC) -o $@ -O2 -Wall $(DUMP_OBJS)

VERIFY_OBJS := verify.o rfc4880.o rsa.o imath.o sha1.o
verify: $(VERIFY_OBJS)
	$(CC) -o $@ $(VERIFY_OBJS)

test: verify
	./verify example/message.txt example/message.sig example/public.gpg

clean:
	rm -f *.o *~ verify rfc4880dump