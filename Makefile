.PHONY: build install uninstall clean

build:
	oasis setup
	ocaml setup.ml -configure --prefix=`opam config var prefix`
	ocaml setup.ml -build

install:
	ocaml setup.ml -install
	make -C plugin/ build
	make -C plugin/ install

uninstall:
	ocamlfind remove bap-veri
	make -C plugin/ uninstall

clean:
	git clean -fdX
	make -C plugin/ clean

test:
	oasis setup
	ocaml setup.ml -configure --prefix=`opam config var prefix` --enable-tests
	ocaml setup.ml -build
	ocaml setup.ml -install
	ocaml setup.ml -test
