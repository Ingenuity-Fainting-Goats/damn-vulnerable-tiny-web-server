CC = clang
CFLAGS = -m32 -fno-stack-protector -z execstack -no-pie  -g 
# LIB = -lpthread

all: tiny-lab1

tiny-lab1: tiny.c
	$(CC) $(CFLAGS) -o tiny-lab1 tiny.c $(LIB)

clean:
	rm -f *.o tiny-lab1 *~
