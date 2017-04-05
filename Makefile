SETUP = ocaml setup.ml

build: setup.ml
	$(SETUP) -build

install:
	$(SETUP) -install
	sh tools/build_plugins.sh plugins bap-veri
	sh tools/build_plugins.sh bap_plugins bap

uninstall:
	$(SETUP) -uninstall $

reinstall:
	make uninstall
	make install

clean:
	$(SETUP) -clean $(BAPCLEANFLAGS)

distclean:
	$(SETUP) -distclean $(BAPDISTCLEANFLAGS)
