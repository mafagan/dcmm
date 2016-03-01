
.PHONY: all install uninstall clean

CC=gcc
INSTALL?=install
INSTALL_DIR=/usr/bin
CFLAGS=-g -fPIC
LFLAGS=-lpthread -levent -lsqlite3 -lssl -llog4c
OBJS=config_manager.o \
	 connection_manager.o \
	 dcmm_utils.o \
	 io_handler.o \
	 logging.o \
	 main.o \
	 mem_cache.o \
	 scheduler.o \
	 session_manager.o \
	 thread_pool.o \
	 http_https.o \
	 memory_pool.o


all: dcmm

dcmm: $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LFLAGS)

config_manager.o: config_manager.c config_manager.h
	$(CC) $(CFLAGS) -c $< -o $@

connection_manager.o: connection_manager.c connection_manager.h
	$(CC) $(CFLAGS) -c $< -o $@

dcmm_utils.o: ../lib/dcmm_utils.c ../lib/dcmm_utils.h
	$(CC) $(CFLAGS) -c $< -o $@

io_handler.o: io_handler.c io_handler.h
	$(CC) $(CFLAGS) -c $< -o $@

logging.o: logging.c logging.h
	$(CC) $(CFLAGS) -c $< -o $@

main.o: main.c
	$(CC) $(CFLAGS) -c $< -o $@

mem_cache.o: mem_cache.c mem_cache.h
	$(CC) $(CFLAGS) -c $< -o $@

scheduler.o: scheduler.c scheduler.h
	$(CC) $(CFLAGS) -c $< -o $@

session_manager.o: session_manager.c session_manager.h
	$(CC) $(CFLAGS) -c $< -o $@

thread_pool.o: thread_pool.c thread_pool.h
	$(CC) $(CFLAGS) -c $< -o $@

http_https.o: http_https.c http_https.h
	$(CC) $(CFLAGS) -c $< -o $@

memory_pool.o: memory_pool.c memory_pool.h
	$(CC) $(CFLAGS) -c $< -o $@

install: all
	$(INSTALL) -d $(INSTALL_DIR)
	$(INSTALL) -s dcmm $(INSTALL_DIR)

uninstall:
	-rm -rf $(INSTALL_DIR)/dcmm

clean:
	-rm dcmm *.o

