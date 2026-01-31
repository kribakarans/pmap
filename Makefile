# Makefile for memmap crash analysis tools

CC = gcc
CFLAGS = -g -O0 -Wall
TARGET = test/crash_demo.out

.PHONY: all clean test

all: $(TARGET)

$(TARGET): test/crash_demo.c
	@echo "Building crash demo test program..."
	$(CC) $(CFLAGS) test/crash_demo.c -o $(TARGET)
	@echo "✓ Built: $(TARGET)"

test: $(TARGET)
	@echo "Running comprehensive crash analysis test suite..."
	./run_all_tests.sh

clean:
	@echo "Cleaning build artifacts..."
	rm -f $(TARGET)
	rm -f crash_dump_*.maps crash_dump_*.regs
	rm -f core.*
	@echo "✓ Clean complete"

help:
	@echo "Makefile for memmap crash analysis tools"
	@echo ""
	@echo "Targets:"
	@echo "  all     - Build crash demo test program (default)"
	@echo "  test    - Build and run comprehensive test suite"
	@echo "  clean   - Remove build artifacts and crash dumps"
	@echo "  help    - Show this help message"
	@echo ""
	@echo "HTML Report Generation:"
	@echo "  Generate HTML visualization of crash dumps:"
	@echo "    ./memmap_analyzer.py crash_dump_<PID>.maps --html report.html"
	@echo "    ./memmap_analyzer.py crash_dump_<PID>.maps --pc 0x<ADDR> --html report.html"
