include ../config.mk

.PHONY: all install uninstall clean reallyclean

ifeq ($(WITH_TLS),yes)
all : mosquitto mosquitto_passwd
else
all : mosquitto
endif

mosquitto : mosquitto.o bridge.o conf.o context.o database.o logging.o loop.o memory_mosq.o persist.o net.o net_mosq.o read_handle.o read_handle_client.o read_handle_server.o read_handle_shared.o security.o security_default.o send_client_mosq.o send_mosq.o send_server.o service.o subs.o sys_tree.o time_mosq.o tls_mosq.o util_mosq.o will_mosq.o
	${CC} $^ -o $@ ${LDFLAGS} $(BROKER_LIBS)

mosquitto.o : mosquitto.c mosquitto_broker.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@ -DCHANGESET=\"$$(cat ../changeset)\"

bridge.o : bridge.c mosquitto_broker.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

conf.o : conf.c mosquitto_broker.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

context.o : context.c mosquitto_broker.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

database.o : database.c mosquitto_broker.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

logging.o : logging.c mosquitto_broker.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

loop.o : loop.c mosquitto_broker.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

memory_mosq.o : memory_mosq.c memory_mosq.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

net.o : net.c mosquitto_broker.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

net_mosq.o : net_mosq.c net_mosq.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

persist.o : persist.c persist.h mosquitto_broker.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

read_handle.o : read_handle.c mosquitto_broker.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

read_handle_client.o : read_handle_client.c mosquitto_broker.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

read_handle_server.o : read_handle_server.c mosquitto_broker.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

read_handle_shared.o : read_handle_shared.c read_handle.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

security.o : security.c mosquitto_broker.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

security_default.o : security_default.c mosquitto_broker.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

send_client_mosq.o : send_client_mosq.c send_mosq.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

send_mosq.o : send_mosq.c send_mosq.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

send_server.o : send_server.c mosquitto_broker.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

service.o : service.c mosquitto_broker.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

subs.o : subs.c mosquitto_broker.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

sys_tree.o : sys_tree.c mosquitto_broker.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

time_mosq.o : time_mosq.c time_mosq.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

tls_mosq.o : tls_mosq.c
	${CC} $(BROKER_CFLAGS) -c $< -o $@

util_mosq.o : util_mosq.c util_mosq.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

will_mosq.o : will_mosq.c will_mosq.h
	${CC} $(BROKER_CFLAGS) -c $< -o $@

mosquitto_passwd : mosquitto_passwd.o
	${CC} $^ -o $@ ${LDFLAGS} $(PASSWD_LIBS)

mosquitto_passwd.o : mosquitto_passwd.c
	${CC} $(CFLAGS) ${CPPFLAGS} -c $< -o $@

install : all
	$(INSTALL) -d ${DESTDIR}$(prefix)/sbin
	$(INSTALL) -s --strip-program=$(STRIP) mosquitto ${DESTDIR}${prefix}/sbin/mosquitto
	$(INSTALL) mosquitto_plugin.h ${DESTDIR}${prefix}/include/mosquitto_plugin.h
ifeq ($(WITH_TLS),yes)
	$(INSTALL) -s --strip-program=$(STRIP) mosquitto_passwd ${DESTDIR}${prefix}/bin/mosquitto_passwd
endif

uninstall :
	-rm -f ${DESTDIR}${prefix}/sbin/mosquitto
	-rm -f ${DESTDIR}${prefix}/include/mosquitto_plugin.h
	-rm -f ${DESTDIR}${prefix}/bin/mosquitto_passwd

clean :
	-rm -f *.o mosquitto mosquitto_passwd

reallyclean : clean
	-rm -rf *.orig *.db
