const express = require(‘express’);
const cors = require(‘cors’);

const app = express();

app.use(cors({
origin: ‘*’,
methods: [‘GET’, ‘POST’, ‘OPTIONS’],
allowedHeaders: [‘Content-Type’, ‘Authorization’]
}));

app.options(’*’, cors());
app.use(express.json());

app.post(’/api/chat’, async (req, res) => {
try {
const response = await fetch(‘https://api.anthropic.com/v1/messages’, {
method: ‘POST’,
headers: {
‘Content-Type’: ‘application/json’,
‘x-api-key’: process.env.ANTHROPIC_API_KEY,
‘anthropic-version’: ‘2023-06-01’
},
body: JSON.stringify(req.body)
});
const data = await response.json();
res.json(data);
} catch (err) {
res.status(500).json({ error: err.message });
}
});

app.get(’/’, (req, res) => res.send(‘Money bot backend running.’));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
