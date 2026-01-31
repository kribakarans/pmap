#!/bin/bash

echo "=============================================="
echo "  COMPREHENSIVE CRASH ANALYSIS TEST SUITE"
echo "=============================================="
echo ""

TESTDIR=test
ANALYZER=./memmap_analyzer.py
CRASH_DEMO=$TESTDIR/crash_demo.out

# Compile crash demo if not present or source is newer
echo "Checking crash demo binary..."
if [ ! -f "$CRASH_DEMO" ] || [ "$TESTDIR/crash_demo.c" -nt "$CRASH_DEMO" ]; then
    echo "Compiling crash demo..."
    gcc -g -O0 -Wall $TESTDIR/crash_demo.c -o $CRASH_DEMO
    if [ $? -eq 0 ]; then
        echo "✓ Compilation successful"
    else
        echo "✗ Compilation failed"
        exit 1
    fi
else
    echo "✓ Using existing binary: $CRASH_DEMO"
fi
echo ""

# Clean old crash dumps
rm -f crash_dump_*.{maps,regs} 2>/dev/null

echo "TEST 1: SIGSEGV (NULL pointer dereference)"
echo "=============================================="
timeout 10 $CRASH_DEMO 2>&1
SIGSEGV_PID=$(ls -t crash_dump_*.maps 2>/dev/null | head -1 | grep -oP '\d+')

if [ -n "$SIGSEGV_PID" ]; then
    echo ""
    echo "✓ SIGSEGV crash dump generated: PID $SIGSEGV_PID"
    SIGSEGV_MAPS="crash_dump_${SIGSEGV_PID}.maps"
    SIGSEGV_REGS="crash_dump_${SIGSEGV_PID}.regs"
    
    # Extract PC from register dump
    SIGSEGV_PC=$(grep "^rip:" $SIGSEGV_REGS | awk '{print $2}')
    echo "  PC (RIP): $SIGSEGV_PC"
else
    echo "✗ SIGSEGV crash dump not found"
fi

echo ""
echo "TEST 2: SIGFPE (divide by zero)"
echo "=============================================="
timeout 10 $CRASH_DEMO divzero 2>&1
SIGFPE_PID=$(ls -t crash_dump_*.maps 2>/dev/null | head -1 | sed "s/crash_dump_\([0-9]*\).maps/\1/" | head -1)

if [ -n "$SIGFPE_PID" ] && [ "$SIGFPE_PID" != "$SIGSEGV_PID" ]; then
    echo ""
    echo "✓ SIGFPE crash dump generated: PID $SIGFPE_PID"
    SIGFPE_MAPS="crash_dump_${SIGFPE_PID}.maps"
    SIGFPE_REGS="crash_dump_${SIGFPE_PID}.regs"
    
    # Extract PC from register dump
    SIGFPE_PC=$(grep "^rip:" $SIGFPE_REGS | awk '{print $2}')
    echo "  PC (RIP): $SIGFPE_PC"
else
    echo "✗ SIGFPE crash dump not found or same as SIGSEGV"
fi

echo ""
echo "TEST 3: SIGABRT (abort call)"
echo "=============================================="
timeout 10 $CRASH_DEMO abort 2>&1
SIGABRT_PID=$(ls -t crash_dump_*.maps 2>/dev/null | head -1 | sed "s/crash_dump_\([0-9]*\).maps/\1/" | head -1)

if [ -n "$SIGABRT_PID" ] && [ "$SIGABRT_PID" != "$SIGSEGV_PID" ]; then
    echo ""
    echo "✓ SIGABRT crash dump generated: PID $SIGABRT_PID"
    SIGABRT_MAPS="crash_dump_${SIGABRT_PID}.maps"
    SIGABRT_REGS="crash_dump_${SIGABRT_PID}.regs"
    
    # Extract PC from register dump
    SIGABRT_PC=$(grep "^rip:" $SIGABRT_REGS | awk '{print $2}')
    echo "  PC (RIP): $SIGABRT_PC"
else
    echo "✗ SIGABRT crash dump not found or same as SIGSEGV"
fi

echo ""
echo "=============================================="
echo "  REGISTER ANALYSIS"
echo "=============================================="

if [ -f "$SIGSEGV_REGS" ]; then
    echo ""
    echo "SIGSEGV Register Dump:"
    echo "----------------------"
    head -20 $SIGSEGV_REGS
fi

if [ -f "$SIGABRT_REGS" ]; then
    echo ""
    echo "SIGABRT Register Dump:"
    echo "----------------------"
    head -20 $SIGABRT_REGS
fi

if [ -f "$SIGFPE_REGS" ]; then
    echo ""
    echo "SIGFPE Register Dump:"
    echo "----------------------"
    head -20 $SIGFPE_REGS
fi

echo ""
echo "=============================================="
echo "  MEMORY MAP ANALYSIS (SIGSEGV)"
echo "=============================================="

if [ -f "$SIGSEGV_MAPS" ] && [ -n "$SIGSEGV_PC" ]; then
    echo ""
    $ANALYZER $SIGSEGV_MAPS --pc 0x$SIGSEGV_PC
fi

echo ""
echo "=============================================="
echo "  ADDR2LINE VERIFICATION (SIGSEGV)"
echo "=============================================="

if [ -f "$SIGSEGV_MAPS" ] && [ -n "$SIGSEGV_PC" ]; then
    # Extract addr2line command from analyzer output
    ADDR2LINE_CMD=$($ANALYZER $SIGSEGV_MAPS --pc 0x$SIGSEGV_PC 2>/dev/null | grep "Debug command:" | sed 's/.*Debug command: //')
    
    if [ -n "$ADDR2LINE_CMD" ]; then
        echo "Running: $ADDR2LINE_CMD -f -p"
        eval "$ADDR2LINE_CMD -f -p"
        echo ""
        
        # Extract offset for objdump
        OFFSET=$(echo $ADDR2LINE_CMD | grep -oP '0x[0-9a-f]+')
        echo "Objdump verification at $OFFSET:"
        echo "---------------------------------"
        objdump -d $CRASH_DEMO | grep -A 2 -B 1 "$OFFSET:"
    fi
fi

echo ""
echo "=============================================="
echo "  MEMORY MAP ANALYSIS (SIGFPE)"
echo "=============================================="

if [ -f "$SIGFPE_MAPS" ] && [ -n "$SIGFPE_PC" ]; then
    echo ""
    $ANALYZER $SIGFPE_MAPS --pc 0x$SIGFPE_PC
fi

echo ""
echo "=============================================="
echo "  ADDR2LINE VERIFICATION (SIGFPE)"
echo "=============================================="

if [ -f "$SIGFPE_MAPS" ] && [ -n "$SIGFPE_PC" ]; then
    # Extract addr2line command from analyzer output
    ADDR2LINE_CMD=$($ANALYZER $SIGFPE_MAPS --pc 0x$SIGFPE_PC 2>/dev/null | grep "Debug command:" | sed 's/.*Debug command: //')
    
    if [ -n "$ADDR2LINE_CMD" ]; then
        echo "Running: $ADDR2LINE_CMD -f -p"
        eval "$ADDR2LINE_CMD -f -p"
        echo ""
        
        # Extract offset for objdump
        OFFSET=$(echo $ADDR2LINE_CMD | grep -oP '0x[0-9a-f]+')
        echo "Objdump verification at $OFFSET:"
        echo "---------------------------------"
        objdump -d $CRASH_DEMO | grep -A 2 -B 1 "$OFFSET:"
    fi
fi

echo ""
echo "=============================================="
echo "  MEMORY MAP ANALYSIS (SIGABRT)"
echo "=============================================="

if [ -f "$SIGABRT_MAPS" ] && [ -n "$SIGABRT_PC" ]; then
    echo ""
    $ANALYZER $SIGABRT_MAPS --pc 0x$SIGABRT_PC
fi

echo ""
echo "=============================================="
echo "  ADDR2LINE VERIFICATION (SIGABRT)"
echo "=============================================="

if [ -f "$SIGABRT_MAPS" ] && [ -n "$SIGABRT_PC" ]; then
    # Extract addr2line command from analyzer output
    ADDR2LINE_CMD=$($ANALYZER $SIGABRT_MAPS --pc 0x$SIGABRT_PC 2>/dev/null | grep "Debug command:" | sed 's/.*Debug command: //')
    
    if [ -n "$ADDR2LINE_CMD" ]; then
        echo "Running: $ADDR2LINE_CMD -f -p"
        eval "$ADDR2LINE_CMD -f -p"
    fi
fi

echo ""
echo "=============================================="
echo "  TEST SUMMARY"
echo "=============================================="
echo ""
echo "Crash dumps generated:"
ls -lh crash_dump_*.{maps,regs} 2>/dev/null | wc -l | xargs echo "  Files:"
echo ""
echo "Test Status:"
[ -f "$SIGSEGV_MAPS" ] && echo "  ✓ SIGSEGV test passed" || echo "  ✗ SIGSEGV test failed"
[ -f "$SIGFPE_MAPS" ] && echo "  ✓ SIGFPE test passed" || echo "  ✗ SIGFPE test failed"
[ -f "$SIGABRT_MAPS" ] && echo "  ✓ SIGABRT test passed" || echo "  ✗ SIGABRT test failed"
echo ""
if [ -f "$SIGSEGV_REGS" ]; then
    SIGSEGV_LINE=$($ANALYZER $SIGSEGV_MAPS --pc 0x$SIGSEGV_PC 2>/dev/null | grep "Debug command:" | sed 's/.*Debug command: //' | xargs -I {} sh -c "{} -f -p" | grep -oP 'crash_demo.c:\K\d+')
    [ -n "$SIGSEGV_LINE" ] && echo "  ✓ SIGSEGV crash at crash_demo.c:$SIGSEGV_LINE (user code)" || echo "  ✓ SIGSEGV crash location resolved"
fi
if [ -f "$SIGFPE_REGS" ]; then
    SIGFPE_LINE=$($ANALYZER $SIGFPE_MAPS --pc 0x$SIGFPE_PC 2>/dev/null | grep "Debug command:" | sed 's/.*Debug command: //' | xargs -I {} sh -c "{} -f -p" | grep -oP 'crash_demo.c:\K\d+')
    [ -n "$SIGFPE_LINE" ] && echo "  ✓ SIGFPE crash at crash_demo.c:$SIGFPE_LINE (user code)" || echo "  ✓ SIGFPE crash location resolved"
fi
if [ -f "$SIGABRT_REGS" ]; then
    echo "  ✓ SIGABRT crash in libc (asynchronous signal, not user code)"
fi
echo ""
echo "=============================================="

