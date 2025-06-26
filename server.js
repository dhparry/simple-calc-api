const express = require('express');
const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static('public')); // serve index.html

// API endpoint
app.post('/api/calculate', (req, res) => {
  const { a, b } = req.body;

  if (typeof a !== 'number' || typeof b !== 'number') {
    return res.status(400).json({ error: 'Invalid input' });
  }

  const result = {
    sum: a + b,
    division: b !== 0 ? a / b : 'undefined'
  };

  res.json(result);
});

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
