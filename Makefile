SERVICE := office-supplies
DESTDIR ?= dist_root
SERVICEDIR ?= /srv/$(SERVICE)

.PHONY: build install

build:

install: build
	mkdir -p $(DESTDIR)$(SERVICEDIR)
	cp -r docker-compose-release.yml $(DESTDIR)$(SERVICEDIR)/docker-compose.yml
	cp -r office-supplies $(DESTDIR)$(SERVICEDIR)/office-supplies
	mkdir -p $(DESTDIR)/etc/systemd/system/faustctf.target.wants/
	ln -s /etc/systemd/system/docker-compose@.service $(DESTDIR)/etc/systemd/system/faustctf.target.wants/docker-compose@office-supplies.service

