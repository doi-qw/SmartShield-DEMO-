class SolidityScannerApp {
    constructor() {
        this.editor = null;
        this.currentScanId = null;
        this.init();
    }

    init() {
        this.initCodeEditor();
        this.bindEvents();
        this.loadDemoContracts();
        this.checkAPIHealth();
    }

    initCodeEditor() {
        this.editor = CodeMirror.fromTextArea(document.getElementById('source-code'), {
            mode: 'solidity',
            theme: 'material-darker',
            lineNumbers: true,
            lineWrapping: true,
            tabSize: 4,
            indentUnit: 4,
            matchBrackets: true,
            autoCloseBrackets: true,
            scrollbarStyle: 'simple',
            extraKeys: {
                'Ctrl-Space': 'autocomplete'
            }
        });
        
        this.editor.setSize('100%', '400px');
    }

    bindEvents() {
        // Scan button
        document.getElementById('scan-btn').addEventListener('click', () => this.scanCode());
        
        // Clear button
        document.getElementById('clear-btn').addEventListener('click', () => this.clearEditor());
        
        // Format button
        document.getElementById('format-btn').addEventListener('click', () => this.formatCode());
        
        // Export buttons
        document.getElementById('export-json').addEventListener('click', () => this.exportResults('json'));
        document.getElementById('export-md').addEventListener('click', () => this.exportResults('markdown'));
        
        // Tab switching
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                
                if (e.target.dataset.tab === 'upload') {
                    this.showUploadDialog();
                }
            });
        });
        
        // Demo contracts
        document.querySelectorAll('.demo-option').forEach(option => {
            option.addEventListener('click', (e) => {
                e.preventDefault();
                const demoType = e.target.closest('.demo-option').dataset.demo;
                this.loadDemoContract(demoType);
            });
        });
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                e.preventDefault();
                this.scanCode();
            }
        });
    }

    async loadDemoContracts() {
        try {
            const response = await fetch('/api/demo-contracts');
            const data = await response.json();
            if (data.success) {
                this.demoContracts = data.demos;
            }
        } catch (error) {
            console.warn('Could not load demo contracts:', error);
        }
    }

    loadDemoContract(type) {
        if (!this.demoContracts || !this.demoContracts[type]) {
            this.showNotification('Demo contract not available', 'error');
            return;
        }
        
        this.editor.setValue(this.demoContracts[type]);
        this.showNotification(`Loaded ${type.replace('-', ' ')} example`, 'success');
        
        // Auto-scroll to scanner
        document.getElementById('scanner').scrollIntoView({ behavior: 'smooth' });
    }

    async checkAPIHealth() {
        try {
            const response = await fetch('/api/health');
            const data = await response.json();
            if (data.status === 'healthy') {
                this.showNotification('API connected successfully', 'success');
            }
        } catch (error) {
            console.warn('API not available:', error);
            this.showNotification('Using local scanner mode', 'warning');
        }
    }

    async scanCode() {
        const sourceCode = this.editor.getValue().trim();
        
        if (!sourceCode) {
            this.showNotification('Please enter Solidity code to scan', 'error');
            return;
        }
        
        // Update UI
        this.showLoading(true);
        this.clearResults();
        
        const options = {
            deepScan: document.getElementById('deep-scan').checked,
            taintAnalysis: document.getElementById('taint-analysis').checked
        };
        
        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    sourceCode,
                    options
                })
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.currentScanId = result.scanId;
                this.displayResults(result);
                this.showNotification(`Scan completed in ${result.results?.stats?.totalTime || 0}ms`, 'success');
            } else {
                throw new Error(result.error || 'Scan failed');
            }
            
        } catch (error) {
            console.error('Scan error:', error);
            this.showError(error.message);
            
            // Fallback to local scanning
            this.tryLocalScan(sourceCode, options);
        } finally {
            this.showLoading(false);
        }
    }

    async tryLocalScan(sourceCode, options) {
        try {
            // Try to load scanner dynamically
            const { IndustrialSecurityScanner } = await import('./scanner.min.js');
            const scanner = new IndustrialSecurityScanner(sourceCode, options);
            const result = scanner.scan();
            
            if (result.success) {
                this.displayResults(result);
                this.showNotification('Scan completed locally', 'success');
            } else {
                throw new Error(result.error);
            }
        } catch (error) {
            this.showError(`Local scan failed: ${error.message}`);
        }
    }

    displayResults(result) {
        const container = document.getElementById('results');
        container.innerHTML = '';
        
        // Show statistics
        if (result.results?.stats) {
            this.displayStatistics(result.results.stats, container);
        }
        
        // Show vulnerabilities
        if (result.results?.vulnerabilities?.length > 0) {
            this.displayVulnerabilities(result.results.vulnerabilities, container);
        }
        
        // Show warnings
        if (result.results?.warnings?.length > 0) {
            this.displayWarnings(result.results.warnings, container);
        }
        
        // Show messages
        if (result.results?.global_msgs?.length > 0) {
            this.displayMessages(result.results.global_msgs, container);
        }
        
        // Show success message if no issues found
        if (!result.results?.vulnerabilities?.length && !result.results?.warnings?.length) {
            this.displaySuccessMessage(container);
        }
    }

    displayStatistics(stats, container) {
        const statsCard = document.createElement('div');
        statsCard.className = 'stats-card';
        
        statsCard.innerHTML = `
            <div class="stats-header">
                <h4><i class="fas fa-chart-bar"></i> Scan Statistics</h4>
                <span class="scan-id">${this.currentScanId}</span>
            </div>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">${stats.totalTime ? stats.totalTime.toFixed(2) : 'N/A'}ms</div>
                    <div class="stat-label">Total Time</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${stats.functionsAnalyzed || 0}</div>
                    <div class="stat-label">Functions Analyzed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value danger">${stats.vulnerabilitiesFound || 0}</div>
                    <div class="stat-label">Vulnerabilities</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value warning">${stats.warningsFound || 0}</div>
                    <div class="stat-label">Warnings</div>
                </div>
            </div>
        `;
        
        container.appendChild(statsCard);
    }

    displayVulnerabilities(vulnerabilities, container) {
        const section = document.createElement('div');
        section.className = 'results-section';
        
        let html = `
            <div class="section-header">
                <h4><i class="fas fa-exclamation-triangle"></i> Vulnerabilities Found (${vulnerabilities.length})</h4>
                <span class="section-badge danger">CRITICAL</span>
            </div>
        `;
        
        vulnerabilities.forEach((vuln, index) => {
            html += `
                <div class="vulnerability-card ${vuln.severity?.toLowerCase() || 'medium'}">
                    <div class="vuln-header">
                        <span class="vuln-index">${index + 1}.</span>
                        <span class="vuln-title">${this.formatVulnerabilityType(vuln.type)}</span>
                        <span class="severity-badge ${vuln.severity?.toLowerCase() || 'medium'}">
                            ${vuln.severity || 'MEDIUM'}
                        </span>
                    </div>
                    <div class="vuln-details">
                        <p><strong>Function:</strong> ${vuln.function || 'Unknown'}</p>
                        <p><strong>Description:</strong> ${vuln.message || 'No description available'}</p>
                        ${vuln.line ? `<p><strong>Line:</strong> ${vuln.line}</p>` : ''}
                        ${vuln.context ? `<p><strong>Context:</strong> <code>${vuln.context}</code></p>` : ''}
                        ${vuln.reentrancyPath ? `
                            <p><strong>Reentrancy Path:</strong></p>
                            <ul>
                                ${vuln.reentrancyPath.map(step => `<li>${step}</li>`).join('')}
                            </ul>
                        ` : ''}
                    </div>
                </div>
            `;
        });
        
        section.innerHTML = html;
        container.appendChild(section);
    }

    displayWarnings(warnings, container) {
        const section = document.createElement('div');
        section.className = 'results-section';
        
        let html = `
            <div class="section-header">
                <h4><i class="fas fa-exclamation-circle"></i> Warnings (${warnings.length})</h4>
                <span class="section-badge warning">WARNINGS</span>
            </div>
        `;
        
        warnings.forEach((warning, index) => {
            html += `
                <div class="warning-card">
                    <div class="warning-header">
                        <span class="warning-index">${index + 1}.</span>
                        <span class="warning-type">${warning.type}</span>
                    </div>
                    <div class="warning-details">
                        <p>${warning.message}</p>
                        ${warning.line ? `<p><strong>Line:</strong> ${warning.line}</p>` : ''}
                    </div>
                </div>
            `;
        });
        
        section.innerHTML = html;
        container.appendChild(section);
    }

    displayMessages(messages, container) {
        const section = document.createElement('div');
        section.className = 'messages-section';
        
        let html = `<h4><i class="fas fa-info-circle"></i> Information</h4><ul>`;
        messages.forEach(msg => {
            html += `<li>${msg}</li>`;
        });
        html += '</ul>';
        
        section.innerHTML = html;
        container.appendChild(section);
    }

    displaySuccessMessage(container) {
        const card = document.createElement('div');
        card.className = 'success-card';
        
        card.innerHTML = `
            <div class="success-icon">
                <i class="fas fa-check-circle"></i>
            </div>
            <h3>No Critical Vulnerabilities Found!</h3>
            <p>Your smart contract passed all security checks.</p>
            <div class="recommendations">
                <p><strong>Recommendations:</strong></p>
                <ul>
                    <li>Always conduct independent security audits</li>
                    <li>Consider formal verification for critical contracts</li>
                    <li>Use multiple security tools for comprehensive coverage</li>
                    <li>Implement bug bounty programs</li>
                </ul>
            </div>
        `;
        
        container.appendChild(card);
    }

    formatVulnerabilityType(type) {
        const types = {
            'REENTRANCY': 'Reentrancy',
            'UNCHECKED_CALL': 'Unchecked Call',
            'ACCESS_CONTROL': 'Access Control',
            'FRONT_RUNNING': 'Front-running',
            'TIMESTAMP_DEPENDENCE': 'Timestamp Dependence',
            'DELEGATECALL': 'Delegatecall Vulnerability',
            'TAINTED_CALL': 'Tainted Call',
            'POTENTIAL_OVERFLOW': 'Potential Overflow',
            'GAS_ISSUE': 'Gas Optimization Issue'
        };
        
        return types[type] || type.replace(/_/g, ' ');
    }

    clearEditor() {
        if (confirm('Clear all code?')) {
            this.editor.setValue('');
            this.showNotification('Editor cleared', 'success');
        }
    }

    formatCode() {
        try {
            const code = this.editor.getValue();
            // Simple formatting (could be enhanced with prettier-solidity)
            const formatted = code
                .replace(/\s+/g, ' ')
                .replace(/\s*{\s*/g, ' {\n')
                .replace(/;\s*/g, ';\n')
                .replace(/}\s*/g, '\n}\n');
            
            this.editor.setValue(formatted);
            this.showNotification('Code formatted', 'success');
        } catch (error) {
            this.showNotification('Formatting failed', 'error');
        }
    }

    exportResults(format) {
        const results = this.getCurrentResults();
        if (!results) {
            this.showNotification('No results to export', 'error');
            return;
        }
        
        let content, mimeType, filename;
        
        if (format === 'json') {
            content = JSON.stringify(results, null, 2);
            mimeType = 'application/json';
            filename = `scan-${this.currentScanId || Date.now()}.json`;
        } else {
            content = this.generateMarkdownReport(results);
            mimeType = 'text/markdown';
            filename = `scan-${this.currentScanId || Date.now()}.md`;
        }
        
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.showNotification(`Report exported as ${format.toUpperCase()}`, 'success');
    }

    getCurrentResults() {
        // In a real app, store results in state
        return null;
    }

    generateMarkdownReport(results) {
        let markdown = `# Security Scan Report\n\n`;
        markdown += `**Scan ID:** ${this.currentScanId || 'N/A'}\n`;
        markdown += `**Timestamp:** ${new Date().toISOString()}\n\n`;
        
        if (results.results?.stats) {
            const stats = results.results.stats;
            markdown += `## Statistics\n\n`;
            markdown += `- **Total Time:** ${stats.totalTime ? stats.totalTime.toFixed(2) : 'N/A'}ms\n`;
            markdown += `- **Functions Analyzed:** ${stats.functionsAnalyzed || 0}\n`;
            markdown += `- **Vulnerabilities Found:** ${stats.vulnerabilitiesFound || 0}\n`;
            markdown += `- **Warnings Found:** ${stats.warningsFound || 0}\n\n`;
        }
        
        if (results.results?.vulnerabilities?.length > 0) {
            markdown += `## Vulnerabilities\n\n`;
            results.results.vulnerabilities.forEach((vuln, i) => {
                markdown += `### ${i + 1}. ${vuln.type} (${vuln.severity})\n\n`;
                markdown += `- **Function:** ${vuln.function || 'Unknown'}\n`;
                markdown += `- **Description:** ${vuln.message || 'No description'}\n`;
                if (vuln.line) markdown += `- **Line:** ${vuln.line}\n`;
                markdown += '\n';
            });
        }
        
        return markdown;
    }

    showUploadDialog() {
        // Implementation for file upload
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.sol,.txt';
        
        input.onchange = (e) => {
            const file = e.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    this.editor.setValue(e.target.result);
                    this.showNotification(`Loaded ${file.name}`, 'success');
                };
                reader.readAsText(file);
            }
        };
        
        input.click();
    }

    showLoading(show) {
        const loading = document.getElementById('loading');
        const scanBtn = document.getElementById('scan-btn');
        
        if (show) {
            loading.style.display = 'block';
            scanBtn.disabled = true;
            scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
        } else {
            loading.style.display = 'none';
            scanBtn.disabled = false;
            scanBtn.innerHTML = '<i class="fas fa-search"></i> Scan for Vulnerabilities';
        }
    }

    clearResults() {
        document.getElementById('results').innerHTML = '';
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <i class="fas fa-${this.getNotificationIcon(type)}"></i>
            <span>${message}</span>
        `;
        
        // Add to page
        document.body.appendChild(notification);
        
        // Remove after delay
        setTimeout(() => {
            notification.classList.add('fade-out');
            setTimeout(() => notification.remove(), 300);
        }, 3000);
        
        // Add CSS for notifications
        if (!document.querySelector('#notification-styles')) {
            const style = document.createElement('style');
            style.id = 'notification-styles';
            style.textContent = `
                .notification {
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    padding: 16px 24px;
                    background: var(--bg-card);
                    border-left: 4px solid;
                    border-radius: 8px;
                    box-shadow: var(--shadow);
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    z-index: 9999;
                    animation: slideIn 0.3s ease;
                }
                .notification.success { border-color: var(--success); }
                .notification.error { border-color: var(--danger); }
                .notification.warning { border-color: var(--warning); }
                .notification.info { border-color: var(--info); }
                @keyframes slideIn {
                    from { transform: translateX(100%); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
                .fade-out {
                    animation: fadeOut 0.3s ease forwards;
                }
                @keyframes fadeOut {
                    to { opacity: 0; transform: translateX(100%); }
                }
            `;
            document.head.appendChild(style);
        }
    }

    getNotificationIcon(type) {
        const icons = {
            'success': 'check-circle',
            'error': 'exclamation-circle',
            'warning': 'exclamation-triangle',
            'info': 'info-circle'
        };
        return icons[type] || 'info-circle';
    }

    showError(message) {
        const container = document.getElementById('results');
        container.innerHTML = `
            <div class="error-card">
                <div class="error-icon">
                    <i class="fas fa-exclamation-circle"></i>
                </div>
                <h3>Scan Failed</h3>
                <p>${message}</p>
                <div class="error-actions">
                    <button class="btn btn-secondary" onclick="window.scannerApp.tryLocalScan()">
                        Try Local Scan
                    </button>
                    <button class="btn btn-primary" onclick="window.scannerApp.scanCode()">
                        Retry
                    </button>
                </div>
            </div>
        `;
    }
}

// Initialize app when page loads
document.addEventListener('DOMContentLoaded', () => {
    window.scannerApp = new SolidityScannerApp();
});

// Add some utility CSS
document.addEventListener('DOMContentLoaded', () => {
    const style = document.createElement('style');
    style.textContent = `
        .error-card {
            text-align: center;
            padding: 40px 20px;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: var(--radius);
            margin: 20px;
        }
        .error-icon {
            font-size: 48px;
            color: var(--danger);
            margin-bottom: 20px;
        }
        .error-actions {
            display: flex;
            gap: 12px;
            justify-content: center;
            margin-top: 20px;
        }
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border);
        }
        .section-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }
        .section-badge.danger {
            background: var(--danger);
            color: white;
        }
        .section-badge.warning {
            background: var(--warning);
            color: black;
        }
    `;
    document.head.appendChild(style);
});
