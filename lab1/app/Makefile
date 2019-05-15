CC = clang-7
CFLAGS = -m32 -fno-stack-protector -z execstack -no-pie  -g 
# LIB = -lpthread

all: tiny-lab1
addressanitizer: tiny-lab1-addressanitizer

tiny-lab1: tiny.c
	$(CC) $(CFLAGS) -o tiny-lab1 tiny.c $(LIB)

tiny-lab1-addressanitizer: tiny.c
	$(CC) $(CFLAGS) -fsanitize=address -g -o tiny-lab1-addressanitizer tiny.c $(LIB)

clean:
	rm -f *.o tiny-lab1* *~
