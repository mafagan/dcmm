include ../config.mk

.PHONY : really clean install

MOSQ_OBJS=mosquitto_dcmm.o \
		  logging_mosq.o \
		  memory_mosq.o \
		  messages_mosq.o \
		  net_mosq.o \
		  read_handle.o \
		  read_handle_client.o \
		  read_handle_shared.o \
		  send_mosq.o \
		  send_client_mosq.o \
		  srv_mosq.o \
		  thread_mosq.o \
		  time_mosq.o \
		  tls_mosq.o \
		  util_mosq.o \
		  will_mosq.o

all : libmosquittodcmm.so.${SOVERSION} libmosquittodcmm.a

install : all
	$(INSTALL) -d ${DESTDIR}$(prefix)/lib${LIB_SUFFIX}/
	$(INSTALL) -s --strip-program=$(STRIP) libmosquittodcmm.so.${SOVERSION} ${DESTDIR}${prefix}/lib${LIB_SUFFIX}/libmosquittodcmm.so.${SOVERSION}
	ln -sf libmosquittodcmm.so.${SOVERSION} ${DESTDIR}${prefix}/lib${LIB_SUFFIX}/libmosquittodcmm.so
	$(INSTALL) -d ${DESTDIR}${prefix}/include/
	$(INSTALL) mosquitto_dcmm.h ${DESTDIR}${prefix}/include/mosquitto_dcmm.h

uninstall :
	-rm -f ${DESTDIR}${prefix}/lib${LIB_SUFFIX}/libmosquittodcmm.so.${SOVERSION}
	-rm -f ${DESTDIR}${prefix}/lib${LIB_SUFFIX}/libmosquittodcmm.so
	-rm -f ${DESTDIR}${prefix}/include/mosquitto_dcmm.h

reallyclean : clean

clean :
	-rm -f *.o libmosquittodcmm.so.${SOVERSION} libmosquittodcmm.so libmosquittodcmm.a

libmosquittodcmm.so.${SOVERSION} : ${MOSQ_OBJS}
	$(CC) -shared $(LIB_LDFLAGS) $^ -o $@ ${LIB_LIBS} ../../dcmm/lib/libdcmm.a

libmosquittodcmm.a : ${MOSQ_OBJS}
	$(AR) cr $@ $^
mosquitto_dcmm.o : mosquitto_dcmm.c mosquitto_dcmm.h
	$(CC) $(LIB_CFLAGS) -c $< -o $@

logging_mosq.o : logging_mosq.c logging_mosq.h
	$(CC) $(LIB_CFLAGS) -c $< -o $@

messages_mosq.o : messages_mosq.c messages_mosq.h
	$(CC) $(LIB_CFLAGS) -c $< -o $@

memory_mosq.o : memory_mosq.c memory_mosq.h
	$(CC) $(LIB_CFLAGS) -c $< -o $@

net_mosq.o : net_mosq.c net_mosq.h
	$(CC) $(LIB_CFLAGS) -c $< -o $@

read_handle.o : read_handle.c read_handle.h
	$(CC) $(LIB_CFLAGS) -c $< -o $@

read_handle_client.o : read_handle_client.c read_handle.h
	$(CC) $(LIB_CFLAGS) -c $< -o $@

read_handle_shared.o : read_handle_shared.c read_handle.h
	$(CC) $(LIB_CFLAGS) -c $< -o $@

send_mosq.o : send_mosq.c send_mosq.h
	$(CC) $(LIB_CFLAGS) -c $< -o $@

send_client_mosq.o : send_client_mosq.c send_mosq.h
	$(CC) $(LIB_CFLAGS) -c $< -o $@

srv_mosq.o : srv_mosq.c
	$(CC) $(LIB_CFLAGS) -c $< -o $@

thread_mosq.o : thread_mosq.c
	$(CC) $(LIB_CFLAGS) -c $< -o $@

time_mosq.o : time_mosq.c
	$(CC) $(LIB_CFLAGS) -c $< -o $@

tls_mosq.o : tls_mosq.c
	$(CC) $(LIB_CFLAGS) -c $< -o $@

util_mosq.o : util_mosq.c util_mosq.h
	$(CC) $(LIB_CFLAGS) -c $< -o $@

will_mosq.o : will_mosq.c will_mosq.h
	$(CC) $(LIB_CFLAGS) -c $< -o $@

