
.PHONY: all install uninstall clean

INSTALL?=install

MOSQ_DIR=mosquitto-1.3.2-with-dcmm

LIB=../lib
LIB_BIN=$(LIB)/bin
LIB_INCLUDE=$(LIB)/include

INSTALL_BIN=/usr/bin
INSTALL_LIB=/usr/lib
INSTALL_INCLUDE=/usr/include

all:
	@set -e; make -C dcmm
	@set -e; make -C $(MOSQ_DIR)
	mkdir -p $(LIB)
	mkdir -p $(LIB_BIN)
	mkdir -p $(LIB_INCLUDE)
	$(INSTALL) dcmm/dcmm.conf $(LIB)
	$(INSTALL) -s dcmm/lib/libdcmm.so $(LIB)
	$(INSTALL) -s dcmm/src/dcmm $(LIB_BIN)
	$(INSTALL) dcmm/lib/dcmm.h $(LIB_INCLUDE)
	$(INSTALL) dcmm/lib/dcmm_utils.h $(LIB_INCLUDE)
	$(INSTALL) $(MOSQ_DIR)/lib/libmosquittodcmm.so.1 $(LIB)
	$(INSTALL) $(MOSQ_DIR)/src/mosquitto $(LIB_BIN)
	$(INSTALL) $(MOSQ_DIR)/src/mosquitto_passwd $(LIB_BIN)
	$(INSTALL) $(MOSQ_DIR)/lib/mosquitto_dcmm.h $(LIB_INCLUDE)

install: all
	mkdir -p $(INSTALL_BIN)
	mkdir -p $(INSTALL_LIB)
	mkdir -p $(INSTALL_INCLUDE)
	$(INSTALL) $(LIB)/dcmm.conf /etc
	$(INSTALL) -s $(LIB)/libdcmm.so $(INSTALL_LIB)
	$(INSTALL) -s $(LIB)/libmosquittodcmm.so.1 $(INSTALL_LIB)
	-rm $(INSTALL_LIB)/libmosquittodcmm.so
	ln -s $(INSTALL_LIB)/libmosquittodcmm.so.1 $(INSTALL_LIB)/libmosquittodcmm.so
	$(INSTALL) -s $(LIB_BIN)/* $(INSTALL_BIN)
	$(INSTALL) $(LIB_INCLUDE)/* $(INSTALL_INCLUDE)

uninstall:
	-rm /etc/dcmm.conf
	-rm $(INSTALL_LIB)/libdcmm.so
	-rm $(INSTALL_LIB)/libmosquittodcmm.so
	-rm $(INSTALL_LIB)/libmosquittodcmm.so.1
	-rm $(INSTALL_BIN)/mosquitto
	-rm $(INSTALL_BIN)/mosquitto_passwd
	-rm $(INSTALL_BIN)/dcmm
	-rm $(INSTALL_INCLUDE)/mosquitto_dcmm.h
	-rm $(INSTALL_INCLUDE)/dcmm.h $(INSTALL_INCLUDE)/dcmm_utils.h

clean:
	-rm -rf ../lib
	@set -e; make -C dcmm clean
	@set -e; make -C $(MOSQ_DIR) clean

