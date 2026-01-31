#!/bin/bash
# Generate HTML reports for all crash dumps

echo "Generating HTML reports for crash analysis..."
echo ""

for maps in crash_dump_*.maps; do
    if [ ! -f "$maps" ]; then
        echo "No crash dumps found."
        exit 0
    fi
    
    pid=$(echo $maps | grep -oP '\d+')
    regs="${maps%.maps}.regs"
    
    if [ ! -f "$regs" ]; then
        echo "Skipping $maps - no register file found"
        continue
    fi
    
    # Extract signal type and PC
    signal=$(grep "^Signal:" "$regs" | awk '{print $2}')
    pc=$(grep "^rip:" "$regs" | awk '{print $2}')
    sp=$(grep "^rsp:" "$regs" | awk '{print $2}')
    
    # Determine signal name
    case $signal in
        11) signame="SIGSEGV" ;;
        8)  signame="SIGFPE" ;;
        6)  signame="SIGABRT" ;;
        *)  signame="SIGNAL${signal}" ;;
    esac
    
    output="crash_${signame}_${pid}.html"
    
    echo "Processing PID $pid ($signame)..."
    ./memmap_analyzer.py "$maps" --pc "0x$pc" --sp "0x$sp" --html "$output"
done

echo ""
echo "HTML reports generated:"
ls -lh crash_*.html
echo ""
echo "Open reports in browser:"
for html in crash_*.html; do
    echo "  file://$(pwd)/$html"
done
