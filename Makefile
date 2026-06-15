# ============================================================
# mole - secrets scanner (CLI + GTK3)
#
#   make          build CLI (mole) and GUI (mole-gui)
#   make cli      build only the command-line tool
#   make gui      build only the GTK3 GUI
#   make run      build + run the CLI on the current directory
#   sudo make install     install both, plus icon + desktop entry
#   sudo make uninstall   remove everything installed above
# ============================================================

CLI_BIN    := mole
GUI_BIN    := mole-gui
VERSION    := 1.0.0
AUTHOR     := Jean-Francois Lachance-Caumartin

PREFIX     ?= /usr/local
BINDIR     := $(PREFIX)/bin
DATADIR    := $(PREFIX)/share
APPDIR     := $(DATADIR)/applications
ICONDIR    := $(DATADIR)/icons/hicolor/scalable/apps

CC         ?= gcc
SRCDIR     := src

# Shared scanning core (no terminal/GUI dependencies)
CORE_SRCS  := $(SRCDIR)/entropy.c $(SRCDIR)/walk.c $(SRCDIR)/rules.c $(SRCDIR)/scan.c
CORE_OBJS  := $(CORE_SRCS:.c=.o)

# CLI-only sources
CLI_SRCS   := $(SRCDIR)/main.c
CLI_OBJS   := $(CLI_SRCS:.c=.o)

# GUI-only sources
GUI_SRCS   := $(SRCDIR)/gui.c
GUI_OBJS   := $(GUI_SRCS:.c=.gui.o)

CFLAGS     := -std=c11 -Wall -Wextra -Wpedantic \
              -O2 -D_FILE_OFFSET_BITS=64        \
              -D_POSIX_C_SOURCE=200809L          \
              -DVERSION=\"$(VERSION)\"
LDFLAGS    := -lm

GTK_CFLAGS := $(shell pkg-config --cflags gtk+-3.0)
GTK_LIBS   := $(shell pkg-config --libs gtk+-3.0)

.PHONY: all cli gui clean run install uninstall

all: cli gui

cli: $(CLI_BIN)
gui: $(GUI_BIN)

$(CLI_BIN): $(CORE_OBJS) $(CLI_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "  Built: $(CLI_BIN) v$(VERSION)"

$(GUI_BIN): $(CORE_OBJS) $(GUI_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(GTK_LIBS) $(LDFLAGS)
	@echo "  Built: $(GUI_BIN) v$(VERSION)"

# core + CLI objects (no GTK headers)
$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -I$(SRCDIR) -c -o $@ $<

# GUI objects need GTK include flags; relax -Wpedantic for GTK macros
$(SRCDIR)/%.gui.o: $(SRCDIR)/%.c
	$(CC) -std=c11 -Wall -Wextra -O2 -D_POSIX_C_SOURCE=200809L \
	    -DVERSION=\"$(VERSION)\" -I$(SRCDIR) $(GTK_CFLAGS) -c -o $@ $<

run: $(CLI_BIN)
	./$(CLI_BIN)

clean:
	rm -f $(CORE_OBJS) $(CLI_OBJS) $(GUI_OBJS) $(CLI_BIN) $(GUI_BIN)
	@echo "  Cleaned build artifacts."

install: all
	@install -d $(DESTDIR)$(BINDIR)
	@install -m 0755 $(CLI_BIN) $(DESTDIR)$(BINDIR)/$(CLI_BIN)
	@install -m 0755 $(GUI_BIN) $(DESTDIR)$(BINDIR)/$(GUI_BIN)
	@install -d $(DESTDIR)$(ICONDIR)
	@install -m 0644 data/mole.svg $(DESTDIR)$(ICONDIR)/mole.svg
	@install -d $(DESTDIR)$(APPDIR)
	@install -m 0644 data/mole.desktop $(DESTDIR)$(APPDIR)/mole.desktop
	-@update-desktop-database $(DESTDIR)$(APPDIR) 2>/dev/null || true
	-@gtk-update-icon-cache -f -t $(DESTDIR)$(DATADIR)/icons/hicolor 2>/dev/null || true
	@echo "  Installed mole v$(VERSION)."

uninstall:
	@rm -f $(DESTDIR)$(BINDIR)/$(CLI_BIN)
	@rm -f $(DESTDIR)$(BINDIR)/$(GUI_BIN)
	@rm -f $(DESTDIR)$(ICONDIR)/mole.svg
	@rm -f $(DESTDIR)$(APPDIR)/mole.desktop
	-@update-desktop-database $(DESTDIR)$(APPDIR) 2>/dev/null || true
	-@gtk-update-icon-cache -f -t $(DESTDIR)$(DATADIR)/icons/hicolor 2>/dev/null || true
	@echo "  Uninstalled."
