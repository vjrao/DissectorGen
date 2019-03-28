all: udp-server tcp-server chat

.PHONY: all

BUILDDIR = ./autogen

udp-server: udp-server.yaml
	./gen_dissector.py udp-server.yaml $(BUILDDIR)/udp-server.lua
	cp $(BUILDDIR)/udp-server.lua ${WIRESHARK_PLUGINS_DIR}

tcp-server: tcp-server.yaml
	./gen_dissector.py tcp-server.yaml $(BUILDDIR)/tcp-server.lua
	cp $(BUILDDIR)/tcp-server.lua ${WIRESHARK_PLUGINS_DIR}

chat: chat.yaml
	./gen_dissector.py chat.yaml $(BUILDDIR)/chat.lua
	cp $(BUILDDIR)/chat.lua ${WIRESHARK_PLUGINS_DIR}
