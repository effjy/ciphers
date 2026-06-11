# Makefile for Ciphers - GTK3 file encryption tool.
#
#   make              build the ./ciphers binary
#   sudo make install   install globally (binary, icon, menu entry)
#   sudo make uninstall remove all installed files
#   make clean        remove build artifacts

VERSION := 1.0.2
BIN      := ciphers

PREFIX  ?= /usr/local
BINDIR  := $(PREFIX)/bin
DATADIR := $(PREFIX)/share
APPDIR  := $(DATADIR)/applications
ICONBASE := $(DATADIR)/icons/hicolor
ICONDIR  := $(ICONBASE)/scalable/apps

# Raster icon sizes installed alongside the scalable SVG so the icon shows
# reliably in the applications menu and the window/taskbar.
ICON_SIZES := 16 24 32 48 64 128 256

CC      ?= cc
PKGS     = gtk+-3.0 libsodium libargon2
CFLAGS  ?= -O2 -Wall -Wextra
CFLAGS  += -DCIPHERS_VERSION=\"$(VERSION)\" $(shell pkg-config --cflags $(PKGS))
LDLIBS  += $(shell pkg-config --libs $(PKGS))

SRC      = src/main.c src/crypto.c src/secure_buffer.c
OBJ      = $(SRC:.c=.o)

.PHONY: all clean install uninstall

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDLIBS)

src/%.o: src/%.c src/crypto.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(BIN)

install: $(BIN)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
	install -d $(DESTDIR)$(ICONDIR)
	install -m 0644 data/ciphers.svg $(DESTDIR)$(ICONDIR)/ciphers.svg
	for s in $(ICON_SIZES); do \
	    install -d $(DESTDIR)$(ICONBASE)/$${s}x$${s}/apps; \
	    install -m 0644 data/ciphers-$${s}.png \
	        $(DESTDIR)$(ICONBASE)/$${s}x$${s}/apps/ciphers.png; \
	done
	install -d $(DESTDIR)$(APPDIR)
	install -m 0644 data/ciphers.desktop $(DESTDIR)$(APPDIR)/ciphers.desktop
	-update-desktop-database $(DESTDIR)$(APPDIR) 2>/dev/null || true
	-gtk-update-icon-cache -f -t $(DESTDIR)$(DATADIR)/icons/hicolor 2>/dev/null || true
	@echo "Ciphers $(VERSION) installed to $(BINDIR)/$(BIN)"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BIN)
	rm -f $(DESTDIR)$(ICONDIR)/ciphers.svg
	for s in $(ICON_SIZES); do \
	    rm -f $(DESTDIR)$(ICONBASE)/$${s}x$${s}/apps/ciphers.png; \
	done
	rm -f $(DESTDIR)$(APPDIR)/ciphers.desktop
	-update-desktop-database $(DESTDIR)$(APPDIR) 2>/dev/null || true
	-gtk-update-icon-cache -f -t $(DESTDIR)$(DATADIR)/icons/hicolor 2>/dev/null || true
	@echo "Ciphers uninstalled"
