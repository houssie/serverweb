CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -pthread -D_GNU_SOURCE
LDFLAGS = -pthread -lcrypto -lssl
TARGET = proxy
SOURCES = proxy.c utils.c logger.c cache.c load_balancer.c backend_manager.c
OBJECTS = $(SOURCES:.c=.o)
HEADERS = config.h logger.h utils.h cache.h load_balancer.h backend_manager.h

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET) proxy.log

install:
	cp $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)

run: $(TARGET)
	./$(TARGET) -p 8085

test: $(TARGET)
	@chmod +x run_tests.sh
	@./run_tests.sh all

test-quick: $(TARGET)
	@chmod +x run_tests.sh
	@./run_tests.sh quick

test-static: $(TARGET)
	@chmod +x run_tests.sh
	@./run_tests.sh static

test-backend: $(TARGET)
	@chmod +x run_tests.sh
	@./run_tests.sh backend

test-cache: $(TARGET)
	@chmod +x run_tests.sh
	@./run_tests.sh cache

test-security: $(TARGET)
	@chmod +x run_tests.sh
	@./run_tests.sh security

test-stress: $(TARGET)
	@chmod +x run_tests.sh
	@./run_tests.sh stress

valgrind: $(TARGET)
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./$(TARGET) -p 8085

debug: $(TARGET)
	gdb ./$(TARGET)

.PHONY: all clean install uninstall run test test-quick test-static test-backend test-cache test-security test-stress valgrind debug