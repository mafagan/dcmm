
.PHONY: all clean

LIBS=-lmosquittodcmm
MACRO=-DVERSION="\"1.2.3\""

all : mosquittodcmm_pub mosquittodcmm_sub pub_simple simple_pub_2 simple_pub_3

mosquittodcmm_pub : pub_client.o
	gcc $< -o $@ $(LIBS) $(MACRO)

mosquittodcmm_sub : sub_client.o
	gcc $< -o $@ $(LIBS) $(MACRO)

pub_simple: pub_simple.o
	gcc $< -o $@ $(LIBS)

simple_pub_2: simple_pub_2.o
	gcc $< -o $@ $(LIBS)

simple_pub_3: simple_pub_3.o
	gcc $< -o $@ $(LIBS)

pub_client.o : pub_client.c
	gcc -c $< -o $@ $(LIBS) $(MACRO)

sub_client.o : sub_client.c
	gcc -c $< -o $@ $(LIBS) $(MACRO)

pub_simple.o : simple_pub_example.c
	gcc -c $< -o $@ $(LIBS)

simple_pub_2.o: simple_pub_2.c
	gcc -c $< -o $@ $(LIBS)

simple_pub_3.o: simple_pub_3.c
	gcc -c $< -o $@ $(LIBS)

clean :
	-rm -f *.o mosquittodcmm_pub mosquittodcmm_sub pub_simple simple_pub_2
