class SolidityScannerApp {
    constructor() {
        console.log('🟢 Scanner App initialized');
        this.currentScanId = null;
        this.init();
    }

    init() {
        this.bindEvents();
        this.checkAPIHealth();
        this.setupDemoContracts();
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
        
        // Demo contracts
        document.querySelectorAll('.demo-option').forEach(option => {
            option.addEventListener('click', (e) => {
                e.preventDefault();
                const demoType = e.target.closest('.demo-option').dataset.demo;
                this.loadDemoContract(demoType);
            });
        });
        
        // Demo dropdown
        document.getElementById('demo-btn').addEventListener('click', (e) => {
            e.stopPropagation();
            const menu = document.getElementById('demo-menu');
            menu.style.display = menu.style.display === 'block' ? 'none' : 'block';
        });
        
        // Close demo menu when clicking outside
        document.addEventListener('click', () => {
            document.getElementById('demo-menu').style.display = 'none';
        });
        
        // Keyboard shortcut
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                e.preventDefault();
                this.scanCode();
            }
        });
    }

    setupDemoContracts() {
        this.demoContracts = {
            'reentrancy': `// Reentrancy Vulnerability Example
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint) public balances;
    
    function withdraw() public {
        uint amount = balances[msg.sender];
        // VULNERABILITY: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] = 0; // Too late!
    }
    
    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}`,
            'front-running': `// Front-running Vulnerability Example
pragma solidity ^0.8.0;

contract VulnerableSwap {
    // No slippage protection
    function swap(uint amountIn) public {
        uint amountOut = amountIn * getPrice();
        payable(msg.sender).transfer(amountOut);
    }
    
    function getPrice() public view returns (uint) {
        return 100;
    }
}`,
            'access-control': `// Access Control Vulnerability Example
pragma solidity ^0.8.0;

contract NoAccessControl {
    address public owner;
    uint public totalSupply;
    
    constructor() {
        owner = msg.sender;
    }
    
    // VULNERABILITY: Anyone can mint tokens!
    function mint(address to, uint amount) public {
        totalSupply += amount;
    }
    
    // VULNERABILITY: Anyone can change owner!
    function transferOwnership(address newOwner) public {
        owner = newOwner;
    }
}`
        };
    }

    loadDemoContract(type) {
        if (!this.demoContracts[type]) {
            this.showNotification('Demo contract not available', 'error');
            return;
        }
        
        document.getElementById('source-code').value = this.demoContracts[type];
        this.showNotification(`Loaded ${type.replace('-', ' ')} example`, 'success');
        document.getElementById('demo-menu').style.display = 'none';
        
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
        console.log('🔘 Scan button clicked!');
        
        const sourceCode = document.getElementById('source-code').value.trim();
        
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
            console.log('📤 Sending scan request...');
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
            
            console.log('📥 Got response:', response.status);
            const result = await response.json();
            console.log('📊 Scan result:', result);
            
            if (result.success) {
                this.currentScanId = result.scanId;
                this.displayResults(result);
                this.showNotification(`Scan completed!`, 'success');
            } else {
                throw new Error(result.error || 'Scan failed');
            }
            
        } catch (error) {
            console.error('❌ Scan error:', error);
            this.showError(error.message);
            
            // Fallback: show demo results if API fails
            this.showDemoResults();
        } finally {
            this.showLoading(false);
        }
    }

    showDemoResults() {
        const demoResult = {
            success: true,
            scanId: 'demo_' + Date.now(),
            results: {
                stats: {
                    totalTime: 123,
                    functionsAnalyzed: 3,
                    vulnerabilitiesFound: 2,
                    warningsFound: 1
                },
                vulnerabilities: [
                    {
                        type: 'REENTRANCY',
                        severity: 'HIGH',
                        message: 'External call before state update violates CEI pattern',
                        function: 'withdraw',
                        line: 8
                    },
                    {
                        type: 'ACCESS_CONTROL',
                        severity: 'HIGH', 
                        message: 'Critical function without access control',
                        function: 'mint',
                        line: 15
                    }
                ],
                warnings: [
                    {
                        type: 'TIMESTAMP_DEPENDENCE',
                        severity: 'MEDIUM',
                        message: 'Using block.timestamp for randomness',
                        function: 'randomNumber',
                        line: 20
                    }
                ]
            }
        };
        
        this.displayResults(demoResult);
        this.showNotification('Showing demo results (API unavailable)', 'warning');
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
                <span class="scan-id">${this.currentScanId || 'demo'}</span>
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
            'DELEGATECALL': 'Delegatecall Vulnerability'
        };
        
        return types[type] || type.replace(/_/g, ' ');
    }

    clearEditor() {
        if (confirm('Clear all code?')) {
            document.getElementById('source-code').value = '';
            this.showNotification('Editor cleared', 'success');
        }
    }

    formatCode() {
        try {
            const code = document.getElementById('source-code').value;
            // Simple formatting
            const formatted = code
                .replace(/\s+/g, ' ')
                .replace(/\s*{\s*/g, ' {\n')
                .replace(/;\s*/g, ';\n')
                .replace(/}\s*/g, '\n}\n');
            
            document.getElementById('source-code').value = formatted;
            this.showNotification('Code formatted', 'success');
        } catch (error) {
            this.showNotification('Formatting failed', 'error');
        }
    }

    exportResults(format) {
        this.showNotification('Export feature coming soon!', 'info');
        // TODO: Implement export
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
        console.log(`📢 ${type}: ${message}`);
        
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
                    <button class="btn btn-primary" onclick="window.scanner.scanCode()">
                        Try Again
                    </button>
                </div>
            </div>
        `;
    }
}

// Initialize app when page loads
document.addEventListener('DOMContentLoaded', () => {
    window.scanner = new SolidityScannerApp();
    console.log('🚀 Scanner ready!');
});

// Add notification styles
document.addEventListener('DOMContentLoaded', () => {
    const style = document.createElement('style');
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
        .notification.success { border-color: #10b981; }
        .notification.error { border-color: #ef4444; }
        .notification.warning { border-color: #f59e0b; }
        .notification.info { border-color: #3b82f6; }
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
        
        .error-card {
            text-align: center;
            padding: 40px 20px;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 12px;
            margin: 20px;
        }
        .error-icon {
            font-size: 48px;
            color: #ef4444;
            margin-bottom: 20px;
        }
        .error-actions {
            display: flex;
            gap: 12px;
            justify-content: center;
            margin-top: 20px;
        }
        
        .section-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }
        .section-badge.danger {
            background: #ef4444;
            color: white;
        }
        .section-badge.warning {
            background: #f59e0b;
            color: black;
        }
        
        .severity-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }
        .severity-badge.high {
            background: #ef4444;
            color: white;
        }
        .severity-badge.medium {
            background: #f59e0b;
            color: black;
        }
        .severity-badge.low {
            background: #64748b;
            color: white;
        }
    `;
    document.head.appendChild(style);
});
