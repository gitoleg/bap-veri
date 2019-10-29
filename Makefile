.PHONY: build install uninstall clean

build:
	oasis setup
	ocaml setup.ml -configure --prefix=`opam config var prefix`
	ocaml setup.ml -build
	ocaml setup.ml -install
	make -C plugin/ build

install:
	make -C plugin/ install

uninstall:
	if [ -f setup.ml ]; then ocaml setup.ml -uninstall; fi
	make -C plugin/ uninstall

clean:
	git clean -fdX
	make -C plugin/ clean
