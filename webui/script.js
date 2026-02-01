// PMAP2HTML Webapp - JavaScript Logic

// ============================================================================
// Data Structures and Constants
// ============================================================================

const SEGMENT_TYPES = {
    CODE: 'CODE',
    DATA: 'DATA',
    RODATA: 'RODATA',
    BSS: 'BSS',
    HEAP: 'HEAP',
    STACK: 'STACK',
    ANON: 'ANON',
    VDSO: 'VDSO',
    UNKNOWN: 'UNKNOWN'
};

const SEGMENT_COLORS = {
    [SEGMENT_TYPES.CODE]: '#4CAF50',
    [SEGMENT_TYPES.DATA]: '#2196F3',
    [SEGMENT_TYPES.RODATA]: '#9C27B0',
    [SEGMENT_TYPES.BSS]: '#FF9800',
    [SEGMENT_TYPES.HEAP]: '#F44336',
    [SEGMENT_TYPES.STACK]: '#00BCD4',
    [SEGMENT_TYPES.ANON]: '#9E9E9E',
    [SEGMENT_TYPES.VDSO]: '#795548',
    [SEGMENT_TYPES.UNKNOWN]: '#607D8B'
};

// ============================================================================
// Memory Map Parser
// ============================================================================

class MemoryMapParser {
    /**
     * Parse /proc/<pid>/maps format
     * Format: start-end perms offset device inode path
     * Example: 0098b000-0098c000 r-xp 00000000 b3:04 6081 /usr/bin/amxrt
     */
    static parse(text) {
        const lines = text.trim().split('\n').filter(line => line.trim());
        const segments = [];
        let processName = 'Unknown';

        for (const line of lines) {
            const segment = this.parseLine(line);
            if (segment) {
                segments.push(segment);
                // Extract process name from first code segment
                if (segment.type === SEGMENT_TYPES.CODE && processName === 'Unknown' && segment.path) {
                    processName = this.extractProcessName(segment.path);
                }
            }
        }

        if (segments.length === 0) {
            throw new Error('No valid memory segments found in input');
        }

        return {
            processName,
            segments,
            minAddr: Math.min(...segments.map(s => s.start)),
            maxAddr: Math.max(...segments.map(s => s.end)),
            timestamp: new Date()
        };
    }

    /**
     * Parse a single line from /proc/<pid>/maps
     */
    static parseLine(line) {
        // Format: address perms offset device inode pathname
        // Example: 0098b000-0098c000 r-xp 00000000 b3:04 6081 /usr/bin/amxrt
        
        const parts = line.split(/\s+/);
        if (parts.length < 5) return null;

        const addressRange = parts[0];
        if (!addressRange.includes('-')) return null;

        const [startStr, endStr] = addressRange.split('-');
        const start = parseInt(startStr, 16);
        const end = parseInt(endStr, 16);

        if (isNaN(start) || isNaN(end)) return null;

        const perms = parts[1];
        const offset = parts[2];
        const device = parts[3];
        const inode = parts[4];
        const path = parts.slice(5).join(' ') || '[anon]';

        const size = end - start;
        const type = this.inferSegmentType(path, perms);

        return {
            start,
            end,
            size,
            permissions: perms,
            offset,
            device,
            inode,
            path,
            type,
            binary: this.normalizePath(path)
        };
    }

    /**
     * Infer segment type from permissions and path
     */
    static inferSegmentType(path, perms) {
        if (path.includes('[heap]')) return SEGMENT_TYPES.HEAP;
        if (path.includes('[stack]')) return SEGMENT_TYPES.STACK;
        if (path.includes('[vdso]')) return SEGMENT_TYPES.VDSO;
        if (path.includes('[anon]')) return SEGMENT_TYPES.ANON;

        if (perms.includes('x')) return SEGMENT_TYPES.CODE;
        if (perms.includes('w') && path !== '[anon]') return SEGMENT_TYPES.DATA;
        if (!perms.includes('w') && !perms.includes('x')) return SEGMENT_TYPES.RODATA;
        if (perms.includes('w') && !perms.includes('x')) return SEGMENT_TYPES.BSS;

        return SEGMENT_TYPES.UNKNOWN;
    }

    /**
     * Normalize path (remove [brackets] labels)
     */
    static normalizePath(path) {
        return path.replace(/\s*\[[^\]]*\]\s*$/, '').trim() || path;
    }

    /**
     * Extract process name from path
     */
    static extractProcessName(path) {
        const parts = path.split('/');
        return parts[parts.length - 1];
    }
}

// ============================================================================
// Memory Map Analyzer
// ============================================================================

class MemoryMapAnalyzer {
    /**
     * Analyze memory map and generate statistics
     */
    static analyze(memoryMap) {
        const stats = {
            totalSegments: memoryMap.segments.length,
            totalMemory: 0,
            segmentsByType: {},
            binaries: {},
            largestSegments: [],
            largestBinaries: []
        };

        // Initialize segment counts
        Object.values(SEGMENT_TYPES).forEach(type => {
            stats.segmentsByType[type] = { count: 0, size: 0 };
        });

        // Analyze segments
        for (const segment of memoryMap.segments) {
            stats.totalMemory += segment.size;
            stats.segmentsByType[segment.type].count++;
            stats.segmentsByType[segment.type].size += segment.size;

            // Track binaries
            const binary = segment.binary;
            if (!stats.binaries[binary]) {
                stats.binaries[binary] = {
                    path: binary,
                    size: 0,
                    segments: [],
                    permissions: new Set()
                };
            }
            stats.binaries[binary].size += segment.size;
            stats.binaries[binary].segments.push(segment);
            stats.binaries[binary].permissions.add(segment.permissions);
        }

        // Find largest segments
        stats.largestSegments = [...memoryMap.segments]
            .sort((a, b) => b.size - a.size)
            .slice(0, 10);

        // Find largest binaries
        stats.largestBinaries = Object.values(stats.binaries)
            .sort((a, b) => b.size - a.size)
            .slice(0, 10);

        return stats;
    }

    /**
     * Format size in bytes to human readable format
     */
    static formatSize(bytes) {
        const units = ['B', 'KB', 'MB', 'GB'];
        let size = bytes;
        let unitIndex = 0;

        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex++;
        }

        return `${size.toFixed(2)} ${units[unitIndex]}`;
    }

    /**
     * Format address in hex
     */
    static formatAddr(addr) {
        return `0x${addr.toString(16).toUpperCase().padStart(8, '0')}`;
    }
}

// ============================================================================
// HTML Generator
// ============================================================================

class HTMLGenerator {
    /**
     * Generate complete visualization HTML
     */
    static generateVisualization(memoryMap, stats) {
        return {
            visualization: this.generateMemoryVisualization(memoryMap),
            statistics: this.generateStatistics(stats),
            files: this.generateFilesSection(memoryMap),
            binaries: this.generateBinariesView(stats),
            details: this.generateDetailsTable(memoryMap),
            legend: this.generateLegend()
        };
    }

    /**
     * Generate memory visualization
     */
    static generateMemoryVisualization(memoryMap) {
        const groupedSegments = this.groupSegmentsForReport(memoryMap.segments);
        let html = '';

        for (const [binary, segments] of Object.entries(groupedSegments)) {
            html += `<tr class="segment-group-row"><td class="segment-group-header" colspan="4">${this.escapeHtml(binary)}</td></tr>`;

            for (const seg of segments) {
                const marker = '';
                const color = SEGMENT_COLORS[seg.type] || SEGMENT_COLORS[SEGMENT_TYPES.UNKNOWN];
                html += `<tr class="segment-row" style="background-color: ${color}33;">`;
                html += `<td class="segment-addr" style="border-left: 3px solid ${color};">${MemoryMapAnalyzer.formatAddr(seg.start)}-${MemoryMapAnalyzer.formatAddr(seg.end)} (${MemoryMapAnalyzer.formatSize(seg.size)})</td>`;
                html += `<td class="segment-perms">${seg.permissions}</td>`;
                html += `<td class="segment-type"><span>${seg.type}</span></td>`;
                html += `<td class="segment-path">${this.escapeHtml(seg.path)}${marker}</td>`;
                html += `</tr>`;
            }
        }

        return html;
    }

    /**
     * Group segments by binary
     */
    static groupSegmentsForReport(segments) {
        const grouped = {
            'Code (.text)': [],
            'Heap': [],
            'Stack': [],
            'BSS / Data': [],
            'Shared Libraries': [],
            'Other': []
        };

        for (const seg of segments) {
            if (seg.path.includes('[heap]')) {
                grouped['Heap'].push(seg);
            } else if (seg.path.includes('[stack]')) {
                grouped['Stack'].push(seg);
            } else if (seg.permissions.includes('x') && !seg.path.includes('/lib') && !seg.path.includes('/usr/lib')) {
                grouped['Code (.text)'].push(seg);
            } else if (seg.path.includes('/lib') || seg.path.includes('/usr/lib')) {
                grouped['Shared Libraries'].push(seg);
            } else if (seg.type === SEGMENT_TYPES.DATA || seg.type === SEGMENT_TYPES.RODATA || seg.type === SEGMENT_TYPES.BSS || seg.type === SEGMENT_TYPES.ANON) {
                grouped['BSS / Data'].push(seg);
            } else {
                grouped['Other'].push(seg);
            }
        }

        Object.keys(grouped).forEach(group => {
            grouped[group].sort((a, b) => a.start - b.start);
            if (grouped[group].length === 0) {
                delete grouped[group];
            }
        });

        return grouped;
    }

    /**
     * Generate statistics cards
     */
    static generateStatistics(stats) {
        const sizeKB = (bytes) => Math.round(bytes / 1024);
        const totalMB = (bytes) => (bytes / (1024 * 1024)).toFixed(1);

        const cards = [
            {
                title: 'Total Segments',
                value: stats.totalSegments
            },
            {
                title: 'Total Memory',
                value: `${totalMB(stats.totalMemory)} MB`
            },
            {
                title: 'CODE',
                value: `${sizeKB(stats.segmentsByType[SEGMENT_TYPES.CODE].size)} KB`
            },
            {
                title: 'DATA',
                value: `${sizeKB(stats.segmentsByType[SEGMENT_TYPES.DATA].size)} KB`
            },
            {
                title: 'HEAP',
                value: `${sizeKB(stats.segmentsByType[SEGMENT_TYPES.HEAP].size)} KB`
            },
            {
                title: 'BINARIES',
                value: Object.keys(stats.binaries).length
            },
            {
                title: 'STACK',
                value: `${sizeKB(stats.segmentsByType[SEGMENT_TYPES.STACK].size)} KB`
            },
            {
                title: 'ANON',
                value: `${sizeKB(stats.segmentsByType[SEGMENT_TYPES.ANON].size)} KB`
            }
        ];

        let cardsHtml = '';
        for (const card of cards) {
            cardsHtml += `
                <div class="stat-card">
                    <h3>${card.title}</h3>
                    <div class="value">${card.value}</div>
                </div>
            `;
        }

        return `
            <div class="section">
                <h2 class="section-title">📈 Memory Stats</h2>
                <div class="stats-grid">
                    ${cardsHtml}
                </div>
            </div>`;
    }

    /**
     * Generate binaries view
     */
    static generateBinariesView(stats) {
        let html = '';

        const binaries = Object.values(stats.binaries)
            .sort((a, b) => b.size - a.size);

        for (const binary of binaries) {
            const perms = Array.from(binary.permissions).join(', ');
            html += `
                <div class="binary-item">
                    <div class="binary-name">${this.escapeHtml(binary.path)}</div>
                    <div class="binary-stats">
                        <div class="binary-stat">
                            <span class="binary-stat-label">Size:</span>
                            <span class="binary-stat-value">${MemoryMapAnalyzer.formatSize(binary.size)}</span>
                        </div>
                        <div class="binary-stat">
                            <span class="binary-stat-label">Segments:</span>
                            <span class="binary-stat-value">${binary.segments.length}</span>
                        </div>
                        <div class="binary-stat">
                            <span class="binary-stat-label">Permissions:</span>
                            <span class="binary-stat-value">${perms}</span>
                        </div>
                    </div>
                </div>
            `;
        }

        return html || '<p>No binaries found</p>';
    }

    /**
     * Generate details table
     */
    static generateDetailsTable(memoryMap) {
        let html = `
            <thead>
                <tr>
                    <th>Start Address</th>
                    <th>End Address</th>
                    <th>Size (bytes)</th>
                    <th>Permissions</th>
                    <th>Type</th>
                    <th>Binary/Mapping</th>
                </tr>
            </thead>
            <tbody>
        `;

        for (const seg of memoryMap.segments) {
            html += `
                <tr>
                    <td class="monospace">${MemoryMapAnalyzer.formatAddr(seg.start)}</td>
                    <td class="monospace">${MemoryMapAnalyzer.formatAddr(seg.end)}</td>
                    <td>${seg.size.toLocaleString()}</td>
                    <td class="monospace">${seg.permissions}</td>
                    <td>${seg.type}</td>
                    <td style="font-size: 0.85em;">${this.escapeHtml(seg.path)}</td>
                </tr>
            `;
        }

        html += `</tbody>`;
        return html;
    }

    /**
     * Generate legend
     */
    static generateLegend() {
        let html = '';

        for (const [type, color] of Object.entries(SEGMENT_COLORS)) {
            html += `
                <div class="legend-item">
                    <div class="legend-color" style="background-color: ${color}"></div>
                    <div class="legend-text"><strong>${type}</strong>: ${this.legendDescription(type)}</div>
                </div>
            `;
        }

        return html;
    }

    static generateFilesSection(memoryMap) {
        const files = {};

        for (const seg of memoryMap.segments) {
            if (!seg.path || seg.path.startsWith('[')) {
                continue;
            }
            if (!files[seg.path]) {
                files[seg.path] = { types: new Set(), size: 0, segments: 0 };
            }
            files[seg.path].types.add(seg.type);
            files[seg.path].size += seg.size;
            files[seg.path].segments += 1;
        }

        const pickType = (typesSet) => {
            const priority = [
                SEGMENT_TYPES.CODE,
                SEGMENT_TYPES.DATA,
                SEGMENT_TYPES.RODATA,
                SEGMENT_TYPES.BSS,
                SEGMENT_TYPES.HEAP,
                SEGMENT_TYPES.STACK,
                SEGMENT_TYPES.ANON,
                SEGMENT_TYPES.VDSO,
                SEGMENT_TYPES.UNKNOWN
            ];
            for (const t of priority) {
                if (typesSet.has(t)) return t;
            }
            return SEGMENT_TYPES.UNKNOWN;
        };

        const fileEntries = Object.keys(files).sort();

        if (fileEntries.length === 0) {
            return `
                <div class="section">
                    <h2 class="section-title">📁 Files</h2>
                    <div class="crash-detail">No file-backed mappings found.</div>
                </div>`;
        }

        let rows = '';
        for (const path of fileEntries) {
            const info = files[path];
            const segType = pickType(info.types);
            const color = SEGMENT_COLORS[segType] || SEGMENT_COLORS[SEGMENT_TYPES.UNKNOWN];
            rows += `
                <tr style="background-color: ${color}33;">
                    <td style="border-left: 3px solid ${color};">${this.escapeHtml(path)}</td>
                    <td class="monospace">${info.segments}</td>
                    <td class="monospace">${info.size.toLocaleString()}</td>
                    <td class="monospace">${segType}</td>
                </tr>`;
        }

        return `
            <div class="section">
                <h2 class="section-title">📁 Files</h2>
                <div style="overflow-x: auto;">
                    <table class="files-table">
                        <thead>
                            <tr>
                                <th>File</th>
                                <th>Segments</th>
                                <th>Total Size (bytes)</th>
                                <th>Type</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${rows}
                        </tbody>
                    </table>
                </div>
            </div>`;
    }

    static legendDescription(type) {
        switch (type) {
            case SEGMENT_TYPES.CODE:
                return 'Executable code segment';
            case SEGMENT_TYPES.DATA:
                return 'Writable data segment';
            case SEGMENT_TYPES.RODATA:
                return 'Read-only data segment';
            case SEGMENT_TYPES.BSS:
                return 'Uninitialized data';
            case SEGMENT_TYPES.HEAP:
                return 'Heap memory region';
            case SEGMENT_TYPES.STACK:
                return 'Stack memory region';
            case SEGMENT_TYPES.ANON:
                return 'Anonymous mapping';
            case SEGMENT_TYPES.VDSO:
                return 'Virtual dynamic shared object';
            default:
                return 'Unknown or special segment';
        }
    }

    /**
     * Generate HTML report (matching Python API structure)
     * @param {Object} memmap - Memory map object
     * @param {Object} crashCtx - Crash context (optional, for future use)
     * @param {string} template - HTML template content
     */
    static generateHtml(memmap, crashCtx, template) {
        const stats = MemoryMapAnalyzer.analyze(memmap);
        const timestamp = new Date().toLocaleString();
        const minAddr = MemoryMapAnalyzer.formatAddr(memmap.minAddr);
        const maxAddr = MemoryMapAnalyzer.formatAddr(memmap.maxAddr);

        // Generate all HTML sections using methods matching Python API
        const segmentsHtml = this._generateSegmentsHtml(memmap, crashCtx);
        const statsHtml = this._generateStatisticsHtml(stats);
        const crashHtml = this._generateCrashHtml(memmap, crashCtx);
        const filesHtml = this._generateFilesHtml(memmap);
        const tableHtml = this._generateTableHtml(memmap);
        const legendHtml = this._generateLegendHtml();

        // Template replacements matching Python API
        const replacements = {
            TITLE: `pmap2html - ${memmap.processName || 'Process'}`,
            PROCESS_NAME: this.escapeHtml(memmap.processName || 'Unknown'),
            PID: 'N/A',
            GENERATED: timestamp,
            STATS_HTML: statsHtml,
            CRASH_HTML: crashHtml,
            FILES_HTML: filesHtml,
            MEMORY_VIS: segmentsHtml,
            LEGEND_HTML: legendHtml,
            DETAILS_TABLE: tableHtml,
            LOW_ADDR: minAddr,
            HIGH_ADDR: maxAddr
        };

        // Replace template placeholders
        return template.replace(/\{\{(\w+)\}\}/g, (match, key) => (
            Object.prototype.hasOwnProperty.call(replacements, key) ? replacements[key] : match
        ));
    }

    /**
     * Generate segments HTML (internal method matching Python API)
     */
    static _generateSegmentsHtml(memmap, crashCtx) {
        return this.generateMemoryVisualization(memmap);
    }

    /**
     * Generate statistics HTML (internal method matching Python API)
     */
    static _generateStatisticsHtml(stats) {
        return this.generateStatistics(stats);
    }

    /**
     * Generate crash context HTML (internal method matching Python API)
     */
    static _generateCrashHtml(memmap, crashCtx) {
        // Crash context support for future enhancement
        return '';
    }

    /**
     * Generate files section HTML (internal method matching Python API)
     */
    static _generateFilesHtml(memmap) {
        return this.generateFilesSection(memmap);
    }

    /**
     * Generate details table HTML (internal method matching Python API)
     */
    static _generateTableHtml(memmap) {
        return `
            <div class="section">
                <h2 class="section-title">📋 Detailed Segment Table</h2>
                <div style="overflow-x: auto;">
                    <table class="files-table">
                        ${this.generateDetailsTable(memmap)}
                    </table>
                </div>
            </div>`;
    }

    /**
     * Generate legend HTML (internal method matching Python API)
     */
    static _generateLegendHtml() {
        return this.generateLegend();
    }

    /**
     * Escape HTML special characters
     */
    static escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// ============================================================================
// UI Controller
// ============================================================================

class UIController {
    constructor() {
        this.currentMemoryMap = null;
        this.currentStats = null;
        this.reportTemplate = null;
        this.setupEventListeners();
    }

    setupEventListeners() {
        // Input tabs
        document.querySelectorAll('.input-tabs .tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.switchInputTab(e));
        });

        // File upload
        document.getElementById('fileSelectBtn').addEventListener('click', () => {
            document.getElementById('fileInput').click();
        });

        document.getElementById('fileInput').addEventListener('change', (e) => {
            this.handleFileSelect(e);
        });

        // Drag and drop
        const uploadArea = document.getElementById('uploadArea');
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('drag-over');
        });

        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('drag-over');
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('drag-over');
            if (e.dataTransfer.files.length > 0) {
                document.getElementById('fileInput').files = e.dataTransfer.files;
                this.handleFileSelect({ target: document.getElementById('fileInput') });
            }
        });

        // Buttons
        document.getElementById('visualiseBtn').addEventListener('click', () => this.visualise());
        document.getElementById('clearBtn').addEventListener('click', () => this.clear());
        document.getElementById('demoBtn').addEventListener('click', () => this.loadDemo());
    }

    switchInputTab(e) {
        const tabName = e.target.dataset.tab;
        document.querySelectorAll('.input-tabs .tab-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        e.target.classList.add('active');

        document.getElementById('uploadTab').classList.remove('active');
        document.getElementById('pasteTab').classList.remove('active');

        const tabContent = document.getElementById(`${tabName}Tab`);
        if (tabContent) {
            tabContent.classList.add('active');
        }
    }

    handleFileSelect(e) {
        const files = e.target.files;
        if (files.length === 0) return;

        const file = files[0];
        const reader = new FileReader();

        const fileNameEl = document.getElementById('uploadFileName');
        if (fileNameEl) {
            fileNameEl.textContent = `Selected file: ${file.name}`;
        }

        reader.onload = (event) => {
            const text = event.target.result;
            document.getElementById('pasteInput').value = text;
        };

        reader.onerror = () => {
            this.showStatus('Error reading file', 'error');
        };

        reader.readAsText(file);
    }

    async visualise() {
        try {
            const inputText = document.getElementById('pasteInput').value.trim();

            if (!inputText) {
                this.showStatus('Please enter or upload a memory map', 'warning');
                return;
            }

            // Parse memory map
            this.currentMemoryMap = MemoryMapParser.parse(inputText);
            this.currentStats = MemoryMapAnalyzer.analyze(this.currentMemoryMap);

            // Save memory map to pmap-report.map file (optional download)
            // this.saveMapFile(inputText);

            // Load template from lib/pmap.html.in
            const template = await this.loadReportTemplate();
            
            // Generate HTML using template-based rendering (matching Python API)
            const reportHtml = HTMLGenerator.generateHtml(this.currentMemoryMap, null, template);
            
            // Open report in new window
            const reportWindow = window.open('', '_blank');

            if (!reportWindow) {
                this.showStatus('Popup blocked. Please allow popups to open the report.', 'warning');
                return;
            }

            reportWindow.document.open();
            reportWindow.document.write(reportHtml);
            reportWindow.document.close();

            this.showStatus(`Opened report for: ${this.currentMemoryMap.processName}`, 'success');

        } catch (error) {
            this.showStatus(`Error: ${error.message}`, 'error');
            console.error(error);
        }
    }

    async loadReportTemplate() {
        if (this.reportTemplate) {
            return this.reportTemplate;
        }

        const response = await fetch('./pmap.html.in');
        if (!response.ok) {
            throw new Error('Failed to load report template (./pmap.html.in)');
        }

        this.reportTemplate = await response.text();
        return this.reportTemplate;
    }

    saveMapFile(mapData) {
        // Save memory map data to pmap-report.map file
        const blob = new Blob([mapData], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'pmap-report.map';
        a.click();
        URL.revokeObjectURL(url);
    }

    loadDemo() {
        const demoWindow = window.open('demo.html', '_blank', 'noopener');
        if (!demoWindow) {
            this.showStatus('Popup blocked. Allow popups to open demo.html.', 'error');
            return;
        }
        this.showStatus('Opened demo.html', 'success');
    }

    clear() {
        document.getElementById('pasteInput').value = '';
        document.getElementById('fileInput').value = '';
        const fileNameEl = document.getElementById('uploadFileName');
        if (fileNameEl) {
            fileNameEl.textContent = '';
        }
        document.getElementById('statusMsg').style.display = 'none';
        this.currentMemoryMap = null;
        this.currentStats = null;
    }

    showStatus(message, type = 'info') {
        const statusMsg = document.getElementById('statusMsg');
        statusMsg.textContent = message;
        statusMsg.className = `status-message ${type}`;
        statusMsg.style.display = 'block';

        if (type === 'success' || type === 'warning') {
            setTimeout(() => {
                statusMsg.style.display = 'none';
            }, 5000);
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    new UIController();
});
