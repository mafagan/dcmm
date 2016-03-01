
.PHONY: all install uninstall clean

CC=gcc
LFLAGS=-L../lib -ldcmm -lpthread -levent -lssl -llog4c
CFLAGS=-g -fPIC -I../lib -I../src

all: client server test client_tls log_test JavaTest.class JavaHttp.class

client: client.o ../lib/libdcmm.so
	$(CC) $(CFLAGS) $< -o $@ $(LFLAGS)

client_tls: client_tls.o ../lib/libdcmm.so
	$(CC) $(CFLAGS) $< -o $@ $(LFLAGS)

server: server.o
	$(CC) $(CFLAGS) $< -o $@ $(LFLAGS)

test: test.o ../src/thread_pool.o
	$(CC) $(CFLAGS) $^ -o $@ $(LFLAGS)

log_test: log_test.o ../src/logging.o ../src/config_manager.o
	$(CC) $(CFLAGS) $^ -o $@ $(LFLAGS)

client.o: client.c ../lib/libdcmm.so
	$(CC) $(CFLAGS) -c $< -o $@

client_tls.o: client_tls.c ../lib/libdcmm.so
	$(CC) $(CFLAGS) -c $< -o $@

server.o: server.c
	$(CC) $(CFLAGS) -c $< -o $@

test.o: test.c
	$(CC) $(CFLAGS) -c $< -o $@

log_test.o: log_test.c
	$(CC) $(CFLAGS) -c $< -o $@

http_test: http_test.c ../lib/libdcmm.so
	$(CC) $(CFLAGS) $< -o $@ $(LFLAGS)

../lib/libdcmm.so:
	$(MAKE) -C ../lib

../src/thread_pool.o:
	$(MAKE) -C ../src

JavaTest.class: JavaTest.java ../jlib/dcmm.jar
	javac -cp .:../jlib/dcmm.jar JavaTest.java

JavaHttp.class: JavaHttp.java ../jlib/dcmm.jar
	javac -cp .:../jlib/dcmm.jar JavaHttp.java

../jlib/dcmm.jar:
	make -C ../jlib

install: all


uninstall:


clean:
	-rm client server test client_tls log_test *.o
	-rm *.class
