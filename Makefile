# Makefile for memmap crash analysis tools

CC = gcc
CFLAGS = -g -O0 -Wall
TARGET = test/crash_demo.out

# Installation directories
INSTALL_DIR ?= $(HOME)/.local/bin
CONFIG_DIR ?= $(HOME)/.local/etc/pmap

.PHONY: all clean test install uninstall help

all: $(TARGET)

$(TARGET): test/crash_demo.c
	@echo "Building crash demo test program..."
	$(CC) $(CFLAGS) test/crash_demo.c -o $(TARGET)
	@echo "Built: $(TARGET)"

test: $(TARGET)
	@echo "Running comprehensive crash analysis test suite..."
	./test/test_all.sh

clean:
	@echo "Cleaning build artifacts..."
	rm -f $(TARGET)
	rm -f crash_dump_*.maps crash_dump_*.regs
	rm -f core.*
	@echo "Clean complete"

install: $(TARGET)
	@echo "Installing pmap tools..."
	install -d -m 755 $(INSTALL_DIR)
	install -d -m 755 $(CONFIG_DIR)
	@echo "Installing executables to $(INSTALL_DIR)..."
	install -m 755 pmap.py $(INSTALL_DIR)/pmap-analyse
	install -m 755 pmap2html.py $(INSTALL_DIR)/pmap2html
	@echo "Installing library to $(CONFIG_DIR)..."
	install -d -m 755 $(CONFIG_DIR)/lib
	install -m 644 lib/*.py $(CONFIG_DIR)/lib/
	@echo "Installation complete"
	@echo ""
	@echo "To use the installed tools, add to your shell config:"
	@echo "  export PATH=\$$HOME/.local/bin:\$$PATH"
	@echo "  export PYTHONPATH=\$$HOME/.local/etc/pmap:\$$PYTHONPATH"

uninstall:
	@echo "Uninstalling pmap tools..."
	@rm -fv $(INSTALL_DIR)/pmap-analyse
	@rm -fv $(INSTALL_DIR)/pmap2html
	@rm -fv $(INSTALL_DIR)/pmap.env
	@rm -rfv $(CONFIG_DIR)
	@echo "Uninstall complete"

help:
	@echo "Makefile for memmap crash analysis tools"
	@echo ""
	@echo "Build Targets:"
	@echo "  all     - Build crash demo test program (default)"
	@echo "  test    - Build and run comprehensive test suite"
	@echo "  clean   - Remove build artifacts and crash dumps"
	@echo ""
	@echo "Installation Targets:"
	@echo "  install   - Install tools to $$HOME/.local/bin and $$HOME/.local/etc/pmap"
	@echo "  uninstall - Remove installed tools"
	@echo ""
	@echo "Usage Examples:"
	@echo "  make              # Build crash demo"
	@echo "  make test         # Run all tests"
	@echo "  make install      # Install tools"
	@echo "  make uninstall    # Uninstall tools"
	@echo ""
	@echo "After installation, add to your shell:"
	@echo "  export PATH=\$$HOME/.local/bin:\$$PATH"
	@echo "  export PYTHONPATH=\$$HOME/.local/etc/pmap:\$$PYTHONPATH"
	@echo ""
	@echo "Then use:"
	@echo "  pmap-analyse /proc/PID/maps"
	@echo "  pmap-analyse --pid <PID> --table"
	@echo "  pmap2html /proc/PID/maps --html report.html"
	@echo "  pmap2html --pid <PID>"
