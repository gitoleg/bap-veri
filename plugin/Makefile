build:
	bapbuild -pkgs monads,bap-main,bap-veri,bap-future veri_bil.plugin
	bapbundle update -desc "verifies bap lifters" veri_bil.plugin

install:
	bapbundle install veri_bil.plugin

uninstall:
	bapbundle remove veri_bil.plugin

clean:
	bapbuild -clean
