.PHONY: all test clean reallyclean 08

CFLAGS=-I../../../lib -I../../../src -Wall -Werror

all : auth_plugin.so 08

08 : 08-tls-psk-pub.test 08-tls-psk-bridge.test

auth_plugin.so : auth_plugin.c
	$(CC) -I../../../src -Wall -Werror -fPIC -shared $^ -o $@

08-tls-psk-pub.test : 08-tls-psk-pub.c ../../../lib/libmosquittodcmm.so.1
	$(CC) -I../../../lib -Wall -Werror $^ -o $@ ../../../lib/libmosquittodcmm.so.1

08-tls-psk-bridge.test : 08-tls-psk-bridge.c ../../../lib/libmosquittodcmm.so.1
	$(CC) -I../../../lib -Wall -Werror $^ -o $@ ../../../lib/libmosquittodcmm.so.1

../../../lib/libmosquittodcmm.so.1:
	make -C ../../../lib

reallyclean : clean
	-rm -f *.orig

clean :
	rm -f *.so *.test
