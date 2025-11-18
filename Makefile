CFLAGS = -g
all:
	cc $(CFLAGS) main.c keyfinder.c aes.c -o keyfinder

test:
	cc -g test-framework/unity.c keyfinder.c aes.c test_keyfinder.c -o test_keyfinder.out
	./test_keyfinder.out

clean:
	rm -rf *.out *.o *.dSYM

.PHONY: test
