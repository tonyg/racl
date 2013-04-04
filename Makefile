COLLECTIONS=racl

all: setup

clean:
	find . -name compiled -type d | xargs rm -rf
	rm -rf racl/private/subnacl

setup:
	raco setup $(COLLECTIONS)

link:
	raco pkg install --link $$(pwd)

unlink:
	raco pkg remove $$(basename $$(pwd))
