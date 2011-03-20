
PROGRAM := GalleryConnector
VERSION := 0.0.0

all: $(PROGRAM).so

clean:
	rm -f $(PROGRAM).c $(PROGRAM).so

install:
	@ [ `whoami` != "root" ] || ( echo 'Run make install as yourself, not as root.' ; exit 1 )
	mkdir -p ~/.gnome2/shotwell/plugins
	install -m 644 $(PROGRAM).so ~/.gnome2/shotwell/plugins

uninstall:
	@ [ `whoami` != "root" ] || ( echo 'Run make install as yourself, not as root.' ; exit 1 )
	rm -f ~/.gnome2/shotwell/plugins/$(PROGRAM).so

$(PROGRAM).so: $(PROGRAM).vala Makefile
	valac --save-temps --main=dummy_main -X -D_VERSION='"$(VERSION)"' --pkg=shotwell-plugin-dev-1.0 --pkg=libsoup-2.4 \
		-X -I/home/nicolas/sources/shotwell \
		-X -DGETTEXT_PACKAGE='"shotwell"' \
		-X --shared -X -fPIC $< RESTSupport.vala -o $@

