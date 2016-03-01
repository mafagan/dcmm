
.PHONY: all dcmm install uninstall clean

DIRS=lib src jlib test
DIRS_INSTALL=lib src

all: dcmm

dcmm:
	@set -e; for d in $(DIRS); do $(MAKE) -C $${d}; done

install: dcmm
	@set -e; for d in $(DIRS_INSTALL); do $(MAKE) -C $${d} install; done
	cp dcmm.conf /etc/

uninstall:
	@set -e; for d in $(DIRS_INSTALL); do $(MAKE) -C $${d} uninstall; done
	-rm /etc/dcmm.conf

clean:
	@set -e; for d in $(DIRS); do $(MAKE) -C $${d} clean; done
