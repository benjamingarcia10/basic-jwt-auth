require('dotenv').config();

const PORT = process.env.PORT || 3000;

const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

app.use(express.json());

const users = [];
let refreshTokens = [];

// Get all created users
app.get('/users', (req, res) => {
    res.json(users);
});

// Get a new access token using refresh token
app.post('/token', (req, res) => {
    const refreshToken = req.body.token;
    if (refreshToken == null) return res.sendStatus(401);
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        const accessToken = generateAccessToken({ 'username': user.username });
        res.json({ 'accessToken': accessToken });
    })
});

// Create a user (sign up)
app.post('/users', async (req, res) => {
    try {
        if (req.body.username == null || req.body.password == null) {
            return res.status(400).send(
                {
                    'success': false,
                    'message': 'Username and password required.'
                });
        }
        if (users.find(user => user.username === req.body.username) != null) {
            return res.status(400).send(
                {
                    'success': false,
                    'message': 'Username already exists.'
                });
        }
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = {
            username: req.body.username,
            password: hashedPassword
        };
        users.push(user);
        return res.status(201).send(
            {
                'success': true,
                'message': 'User created.'
            });
    } catch (err) {
        return res.status(500).send({
            'success': false,
            'message': err.message
        });
    }
});

// Login a user (sign in)
app.post('/login', async (req, res) => {
    if (req.body.username == null || req.body.password == null) {
        return res.status(400).send(
            {
                'success': false,
                'message': 'Username and password required.'
            });
    }
    const user = users.find(user => user.username === req.body.username);
    if (user == null) {
        return res.status(400).send(
            {
                'success': false,
                'message': 'Cannot find user.'
            });
    }
    try {
        if (await bcrypt.compare(req.body.password, user.password)) {
            const currentUser = { 'username': user.username }
            const accessToken = generateAccessToken(currentUser);
            const refreshToken = jwt.sign(currentUser, process.env.REFRESH_TOKEN_SECRET);
            refreshTokens.push(refreshToken);
            return res.send({
                'success': true,
                'message': 'User logged in.',
                'accessToken': accessToken,
                'refreshToken': refreshToken
            });
        } else {
            return res.send({
                'success': false,
                'message': 'Invalid password.'
            });
        }
    } catch (err) {
        return res.status(500).send({
            'success': false,
            'message': err.message
        });
    }
});

app.delete('/logout', (req, res) => {
    refreshTokens = refreshTokens.filter(token => token !== req.body.token);
    res.sendStatus(204);
})

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '30s' });
}

app.listen(PORT, () => console.log(`Listening on http://localhost:${PORT}/`));
