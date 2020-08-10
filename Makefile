PREFIX ?= /usr
LIBDIR ?= $(PREFIX)/lib
PYTHON3_MODDIR ?= python3
INSTALL ?= install

#--------

define sep


endef

all:
	@:

install:
	$(INSTALL) -D -m 0755 aa-scan3 $(DESTDIR)$(PREFIX)/bin/aa-scan3
	$(foreach p,$(wildcard aa_scan3/utils.py aa_scan3/plugins/*.py), \
		$(INSTALL) -D -m 0644 $(p) $(DESTDIR)$(LIBDIR)/$(PYTHON3_MODDIR)/$(p)$(sep) \
	)
