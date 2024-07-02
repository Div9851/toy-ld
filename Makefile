CC = gcc
OBJS = main.o vec.o hashmap.o
PROGRAM = toy-ld

$(PROGRAM): $(OBJS)
	$(CC) $(OBJS) -o $(PROGRAM)

.PHONY: test
test: $(PROGRAM)
	./test.sh

.PHONY: clean
clean:
	find . -name "*.o" -type f -delete
	rm -f a.out $(PROGRAM)
