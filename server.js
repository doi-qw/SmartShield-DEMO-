require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const { IndustrialSecurityScanner } = require('./scanner');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"]
    }
  }
}));

// CORS configuration
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://scanner.yourdomain.com'] 
    : '*',
  credentials: true
}));

// Logging
app.use(morgan('combined'));

// Body parsing
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

// API Routes
app.use('/api/', apiLimiter);

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Solidity Security Scanner API',
    version: '2.0.0',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// Scan endpoint
app.post('/api/scan', async (req, res) => {
  try {
    const { sourceCode, options = {} } = req.body;
    
    // Validation
    if (!sourceCode || typeof sourceCode !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Source code is required and must be a string'
      });
    }
    
    if (sourceCode.length > 100000) {
      return res.status(400).json({
        success: false,
        error: 'Source code too large (max 100KB)'
      });
    }
    
    console.log(`[API] Scanning request: ${sourceCode.length} chars`);
    
    // Initialize scanner
    const scanner = new IndustrialSecurityScanner(sourceCode, {
      ENABLE_SYMBOLIC_EXECUTION: options.deepScan || false,
      ENABLE_TAINT_ANALYSIS: true,
      TIMEOUT_MS: 30000
    });
    
    const result = scanner.scan();
    
    res.json({
      success: true,
      scanId: `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString(),
      ...result
    });
    
  } catch (error) {
    console.error('[API] Scan error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error during scan',
      message: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Demo contracts
app.get('/api/demo-contracts', (req, res) => {
  const demos = {
    'reentrancy': `// Reentrancy Vulnerability Example
pragma solidity ^0.8.4;

contract VulnerableBank {
    mapping(address => uint) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // REENTRANCY VULNERABILITY!
    function withdraw() public {
        uint amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] = 0; // State update AFTER external call!
    }
}`,
    'front-running': `// Front-running Vulnerability Example
pragma solidity ^0.8.4;

contract VulnerableExchange {
    // No slippage protection
    function swapTokens(uint amountIn) public {
        // Simple swap without price impact protection
        uint amountOut = amountIn * getPrice();
        payable(msg.sender).transfer(amountOut);
    }
    
    function getPrice() public view returns (uint) {
        return 100; // Fixed price for demo
    }
}`,
    'access-control': `// Access Control Vulnerability Example
pragma solidity ^0.8.4;

contract AdminVulnerable {
    address public owner;
    uint public totalSupply;
    
    constructor() {
        owner = msg.sender;
    }
    
    // Missing onlyOwner modifier!
    function mint(address to, uint amount) public {
        totalSupply += amount;
        // Mint logic...
    }
    
    function transferOwnership(address newOwner) public {
        // No access control!
        owner = newOwner;
    }
}`
  };
  
  res.json({ success: true, demos });
});

// Catch-all route for SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`
  🚀 Solidity Security Scanner v2.0.0
  📡 Server running on port ${PORT}
  🌐 Web interface: http://localhost:${PORT}
  🔧 API endpoint: http://localhost:${PORT}/api/scan
  📊 Health check: http://localhost:${PORT}/api/health
  `);
});

module.exports = app;
