CFLAGS = -g
all:
	gcc $(CFLAGS) main.c keyfinder.c -o keyfinder

test:
	gcc -g test-framework/unity.c keyfinder.h keyfinder.c aes.h aes.c test_keyfinder.c -o test_keyfinder.out
	./test_keyfinder.out

clean:
	rm -rf *.out *.o *.dSYM

.PHONY: test
