require('dotenv').config();

const PORT = process.env.PORT || 4000;

const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');

app.use(express.json());

// Get current user
app.get('/user', authenticateToken, (req, res) => {
    res.json(
        {
            'currentUser': req.user.username,
        });
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']; // Bearer TOKEN
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

app.listen(PORT, () => console.log(`Listening on http://localhost:${PORT}/`));
