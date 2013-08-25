all: setup

clean:
	find . -name compiled -type d | xargs rm -rf
	rm -rf private/subnacl

setup:
	raco setup $$(basename $$(pwd))

link:
	raco pkg install --link $$(pwd)

unlink:
	raco pkg remove $$(basename $$(pwd))
