ifeq ($(shell uname -s),Darwin)
SHEXT=dylib
else
SHEXT=so
endif

SHAREDLIB=nacl.$(SHEXT)
NACLVERSION=20110221
NACLUNPACKED=nacl-$(NACLVERSION)

all: $(SHAREDLIB)

$(SHAREDLIB): subnacl
	raco ctool ++ldf "-I" ++ldf "subnacl/include" --ld $@ `find subnacl -name '*.c'`

clean:
	rm -f $(SHAREDLIB)
	rm -rf subnacl
	rm -rf $(NACLUNPACKED)

subnacl: import.py $(NACLUNPACKED)
	python import.py $(NACLUNPACKED)

$(NACLUNPACKED): $(NACLUNPACKED).tar.bz2
	tar -jxvf $<
