
.PHONY: all install uninstall clean

CC=gcc
INSTALL?=install
INSTALL_DIR=/usr
CFLAGS=-g -fPIC
LFLAGS=-lpthread
OBJS=dcmm.o \
	 dcmm_utils.o

all: libdcmm.so libdcmm.a

libdcmm.so: $(OBJS)
	$(CC) $(CFLAGS) -shared $^ -o $@ $(LFLAGS)

libdcmm.a: $(OBJS)
	$(AR) cr $@ $^

dcmm.o: dcmm.c dcmm.h
	$(CC) $(CFLAGS) -c $< -o $@

dcmm_utils.o: dcmm_utils.c dcmm_utils.h
	$(CC) $(CFLAGS) -c $< -o $@

install: all
	$(INSTALL) -d $(INSTALL_DIR)/lib
	$(INSTALL) -s libdcmm.so $(INSTALL_DIR)/lib
	$(INSTALL) -s libdcmm.a $(INSTALL_DIR)/lib
	$(INSTALL) -d $(INSTALL_DIR)/include
	$(INSTALL) dcmm.h $(INSTALL_DIR)/include
	$(INSTALL) dcmm_utils.h $(INSTALL_DIR)/include

uninstall:
	-rm -rf $(INSTALL_DIR)/lib/libdcmm.so
	-rm -rf $(INSTALL_DIR)/lib/libdcmm.a
	-rm -rf $(INSTALL_DIR)/include/dcmm.h
	-rm -rf $(INSTALL_DIR)/include/dcmm_utils.h

clean:
	-rm *.so *.a *.o
