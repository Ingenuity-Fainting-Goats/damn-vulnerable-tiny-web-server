CC = clang-7
CFLAGS = -m32 -fno-stack-protector -z noexecstack -no-pie  -g 
# LIB = -lpthread

all: tiny-lab2
addressanitizer: tiny-lab2-addressanitizer

tiny-lab2: tiny.c
	$(CC) $(CFLAGS) -o tiny-lab2 tiny.c $(LIB)

tiny-lab2-addressanitizer: tiny.c
	$(CC) $(CFLAGS) -fsanitize=address -g -o tiny-lab2-addressanitizer tiny.c $(LIB)

clean:
	rm -f *.o tiny-lab2* *~
