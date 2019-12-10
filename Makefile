.PHONY: build install uninstall clean

build:
	oasis setup
	ocaml setup.ml -configure --prefix=`opam config var prefix`
	ocaml setup.ml -build

install: install_plugin

uninstall:
	ocamlfind remove bap-veri
	ocamlfind remove bap-plugin-veri
	bapbundle remove veri.plugin

clean:
	git clean -fdX

install_libs:
	ocaml setup.ml -install

install_plugin: install_libs
	sh tools/build_plugin.sh

test:
	oasis setup
	ocaml setup.ml -configure --prefix=`opam config var prefix` --enable-tests
	ocaml setup.ml -build
	ocaml setup.ml -install
	ocaml setup.ml -test

reinstall: uninstall install
