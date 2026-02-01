# PMAP2HTML Webapp

A static, client-side web application for visualizing Linux process memory maps interactively. Built with vanilla HTML5, CSS3, and JavaScript (no dependencies).

## Features

- **File Upload**: Drag & drop or select `.maps` files
- **Paste Input**: Copy-paste memory map data directly
- **Report Output**: Opens in a new tab using the pmap.html template
- **Memory Visualization**: Color-coded segments by type (CODE, DATA, HEAP, STACK, etc.)
- **Statistics**: View memory usage statistics by type
- **Details Table**: Complete table of all memory segments
- **Responsive Design**: Works on desktop, tablet, and mobile
- **Fast & Lightweight**: No backend server required, runs entirely in browser

## Quick Start

### Local Usage

1. Open `index.html` in a modern web browser
2. Either:
    - Upload a `.maps` file (e.g., from `cat /proc/PID/maps > dump.txt`)
    - Paste memory map content directly
3. Click "Visualise" to generate the report
4. The report opens in a new tab using `pmap.html`

### Getting Memory Map Data

From a running process:
```bash
cat /proc/PID/maps > memory_dump.txt
```

From a crash dump file:
```bash
./pmap.py crash_dump.maps
```

## Deployment to GitHub Pages

### Option 1: Serve from Root

1. Place webapp files in repository root
2. Enable GitHub Pages on main branch
3. Access at `https://username.github.io/memmap/`

### Option 2: Serve from `/webapp/` Directory

1. Keep webapp in `/webapp/` folder
2. Configure GitHub Pages to serve from `/webapp/` branch
3. Access at `https://username.github.io/memmap/webapp/`

### Option 3: Create `gh-pages` Branch

```bash
# Create and checkout orphan gh-pages branch
git checkout --orphan gh-pages
git reset --hard
git clean -fd

# Copy webapp files to root
cp -r webapp/* .
git add .
git commit -m "Initial GitHub Pages deployment"
git push -u origin gh-pages

# Switch back to main
git checkout main
```

Then enable GitHub Pages from `gh-pages` branch in repository settings.

## File Structure

```
webapp/
├── index.html           # Main HTML structure
├── style.css           # Complete styling (responsive)
├── script.js           # Vanilla JavaScript logic
├── pmap.html           # Report template (opened in new tab)
├── PLAN.md            # Development plan
├── README.md          # This file
└── .nojekyll          # (optional) For GitHub Pages
```

## Technical Details

### Data Flow

```
Input (file/paste)
    ↓
MemoryMapParser.parse()
    ↓
MemoryMap Object
    ↓
MemoryMapAnalyzer.analyze()
    ↓
Statistics Object
    ↓
HTMLGenerator.generateFullReportHtml(template)
    ↓
New tab report rendering
```

### Segment Type Detection

- **CODE**: `r-xp` permission
- **DATA**: `rw-p` permission, file-backed
- **RODATA**: `r--p` permission
- **BSS**: `rw-p` permission, anonymous
- **HEAP**: `[heap]` annotation
- **STACK**: `[stack]` annotation
- **VDSO**: `[vdso]` annotation
- **ANON**: Other anonymous regions
- **UNKNOWN**: Unable to determine

### Color Scheme

| Type | Color |
|------|-------|
| CODE | Green (#4CAF50) |
| DATA | Blue (#2196F3) |
| RODATA | Purple (#9C27B0) |
| BSS | Orange (#FF9800) |
| HEAP | Red (#F44336) |
| STACK | Cyan (#00BCD4) |
| ANON | Gray (#9E9E9E) |
| VDSO | Brown (#795548) |

## Browser Support

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+
- iOS Safari 14+
- Android Chrome

## Performance

- Handles memory maps with 100+ segments smoothly
- Optimized DOM manipulation with documentFragment
- Lazy rendering for large datasets
- Efficient CSS with minimal reflows

## Troubleshooting

### "No valid memory segments found"
- Ensure input format matches `/proc/<pid>/maps`
- Each line should have: `address perms offset device inode pathname`
- Example valid line: `0098b000-0098c000 r-xp 00000000 b3:04 6081 /usr/bin/amxrt`

### File not loading
- Check file format (must be text)
- Try paste mode instead
- Verify browser console for errors (F12)

### Report does not open
- Allow popups for this site (the report opens in a new tab)
- Ensure pmap.html is present and accessible

## Development

### Architecture

1. **Parser** (`MemoryMapParser`): Parses `/proc/<pid>/maps` format
2. **Analyzer** (`MemoryMapAnalyzer`): Calculates statistics and groups data
3. **Generator** (`HTMLGenerator`): Creates HTML visualizations
4. **Controller** (`UIController`): Manages UI interactions and state

### Adding Features

To add new features:

1. Extend data in `MemoryMapAnalyzer.analyze()`
2. Create new generator method in `HTMLGenerator`
3. Add UI element in `index.html`
4. Update `UIController` to handle interaction
5. Add styling to `style.css`

### Testing Locally

```bash
# Serve locally with Python
python3 -m http.server 8000

# Then open browser to http://localhost:8000/webapp/
```

## Comparison with Python Tools

| Feature | Webapp | pmap.py | pmap2html.py |
|---------|--------|---------|-------------|
| Installation | None | Required | Required |
| Dependencies | None | lib/ | lib/ |
| Deployment | GitHub Pages | CLI | CLI |
| Crash Context | Not yet | Yes | Yes |
| Visualization | Interactive | Terminal | Static HTML |
| Export | HTML | Text | HTML |

## Future Enhancements

- [ ] Crash context highlighting (PC, LR, SP)
- [ ] Address range search/filter
- [ ] Keyboard navigation
- [ ] Dark mode toggle
- [ ] LocalStorage for recent dumps
- [ ] Diff view (compare two memory maps)
- [ ] Memory layout ASCII diagram
- [ ] Heatmap visualization

## License

Same as parent project

## Contributing

Contributions welcome! Areas for improvement:
- Performance optimization
- Additional visualizations
- Mobile UI improvements
- Accessibility enhancements
- Internationalization

---

**Quick Links:**
- [Memory Map Format](https://man7.org/linux/man-pages/man5/proc.5.html) - Linux proc(5) documentation
- [Source Repository](https://github.com) - Main project
- [Issues](https://github.com/issues) - Bug reports and feature requests
