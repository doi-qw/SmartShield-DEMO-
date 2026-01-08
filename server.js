const express = require('express');
const cors = require('cors');
const { analyzeSource } = require('./solidity_scanner_ast');

const app = express();

app.use(cors());
app.use(express.json({ limit: '2mb' }));

app.post('/scan', (req, res) => {
  const code = req.body?.code;

  if (!code || code.trim().length < 10) {
    return res.status(400).json({
      error: 'Code missing or too short',
      functions: [],
      global_msgs: []
    });
  }

  try {
    const result = analyzeSource(code);
    res.json(result);
  } catch (e) {
    res.status(500).json({
      error: e.message,
      functions: [],
      global_msgs: []
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🔥 Solidity Scanner API running on port ${PORT}`);
});
