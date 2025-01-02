NAME=weight-generator
CC=clang
CFLAGS=-g -Wall -Wextra -Werror -fsanitize=address -fsanitize=undefined

all: clean build

build: weight_generator.c
	$(CC) $(CFLAGS) -o $(NAME) $^

clean:
	rm -f $(NAME)
