
.PHONY: all install JAVA.class

all: dcmm.jar libdcmmjni.so

install:


dcmm_Dcmm.o: dcmm_Dcmm.c
	gcc -g -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux -c $< -o $@

../lib/dcmm_utils.o: ../lib/dcmm_utils.c
	gcc -g -c $< -o $@

libdcmmjni.so: dcmm_Dcmm.o ../lib/dcmm_utils.o
	gcc -g -fPIC -shared $^ -o $@

dcmm.jar:
	make -C dcmm
	jar cvf dcmm.jar dcmm/*.class

clean:
	make -C dcmm clean
	-rm libdcmmjni.so
	-rm *.o
	-rm dcmm.jar
