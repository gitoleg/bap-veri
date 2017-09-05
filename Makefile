SETUP = ocaml setup.ml

build: setup.ml
	$(SETUP) -build

install:
	$(SETUP) -install
	sh tools/build_plugins.sh plugins
	sh tools/build_plugins.sh bap_plugins

uninstall:
	$(SETUP) -uninstall $
	sh tools/remove_plugins.sh

reinstall:
	make uninstall
	make install

clean:
	$(SETUP) -clean $(BAPCLEANFLAGS)

distclean:
	$(SETUP) -distclean $(BAPDISTCLEANFLAGS)
