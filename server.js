require('dotenv').config();

const PORT = process.env.PORT || 3000;

const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

app.use(express.json());

const users = [];

// Get all created users
app.get('/users', authenticateToken, (req, res) => {
    res.json(
        {
            'currentUser': req.user.username,
            'users': users
        });
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
app.post('/users/login', async (req, res) => {
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
            const accessToken = jwt.sign({ username: user.username }, process.env.ACCESS_TOKEN_SECRET);
            return res.send({
                'success': true,
                'message': 'User logged in.',
                'accessToken': accessToken
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
