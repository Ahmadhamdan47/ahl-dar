// server.js
const express = require('express');
const bcrypt = require('bcryptjs');
const cors = require('cors');  // Add this

const jwt = require('jsonwebtoken');
const connection = require('./db');
const dotenv = require('dotenv');
dotenv.config();

const app = express();
app.use(express.json());

// JWT secret for token signing
const JWT_SECRET = process.env.JWT_SECRET;
app.use(cors({
    origin: 'http://localhost:3001',  // Allow only this origin, or use '*' to allow all origins
}));
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization']; // Get the token from the Authorization header
    const token = authHeader && authHeader.split(' ')[1]; // Bearer token format
  
    if (token == null) return res.status(401).json({ error: 'No token provided, authorization denied' });
  
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.status(403).json({ error: 'Token is not valid' });
  
      req.user = user; // Attach the decoded user info to the request
      next(); // Proceed to the next middleware or route handler
    });
  };
// Sign-up route (with phone number and password)
// Updated sign-up route in server.js
// Updated sign-up route in server.js with detailed error logging
app.post('/signup', async (req, res) => {
    const { phoneNumber, password, name, email, address, city, region, district, age, sex } = req.body;

    if (!phoneNumber || !password || !name || !email || !address || !city || !region || !district || !age || !sex) {
        console.log('Validation error: Missing required fields');
        return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if user already exists
    connection.query('SELECT * FROM users WHERE phone_number = ? OR email = ?', [phoneNumber, email], async (err, results) => {
        if (err) {
            console.error('Database query error:', err);  // Log the error
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length > 0) {
            console.log('User already exists with the given phone number or email');
            return res.status(400).json({ error: 'User with this phone number or email already exists' });
        }

        // Hash the password before saving
        try {
            const hashedPassword = await bcrypt.hash(password, 10);

            // Insert user details into the database
            const sql = `
                INSERT INTO users (phone_number, password, name, email, address, city, region, district, age, sex)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `;
            connection.query(sql, [phoneNumber, hashedPassword, name, email, address, city, region, district, age, sex], (err, results) => {
                if (err) {
                    console.error('Database insert error:', err);  // Log the error
                    return res.status(500).json({ error: 'Failed to register user' });
                }
                console.log('User registered successfully');
                res.status(201).json({ message: 'User registered successfully' });
            });
        } catch (hashError) {
            console.error('Password hashing error:', hashError);  // Log the hashing error
            return res.status(500).json({ error: 'Failed to hash password' });
        }
    });
});


// Login route (with phone number and password)
app.post('/login', async (req, res) => {
    const { phoneNumber, password } = req.body;

    if (!phoneNumber || !password) {
        return res.status(400).json({ error: 'Phone number and password are required' });
    }

    // Check if the user exists
    connection.query('SELECT * FROM users WHERE phone_number = ?', [phoneNumber], async (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(400).json({ error: 'User does not exist' });

        const user = results[0];

        // Compare the provided password with the hashed password in the database
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

        // Generate a JWT token
        const token = jwt.sign({ id: user.id, phoneNumber: user.phone_number, role: user.role }, JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ message: 'Login successful', token });
    });
});

// Protected route (example, only accessible with a valid token)
app.get('/protected', (req, res) => {
    const token = req.headers['authorization'];

    if (!token) return res.status(401).json({ error: 'Token is required' });

    // Verify the token
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Invalid token' });

        res.status(200).json({ message: 'Access granted to protected route', user: decoded });
    });
});
app.get('/houses', (req, res) => {
    connection.query('SELECT * FROM houses', (err, results) => {
        if (err) {
            console.error('Error fetching house listings:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.status(200).json(results);
    });
});

// Add a new house listing
app.post('/houses', authenticateToken, (req, res) => {
    const {
        address, region, district, town, size, capacity, photos, furnished, for_rent, rent_amount, phone_number
    } = req.body;

    if (!address || !region || !district || !town || !phone_number) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const sql = `
        INSERT INTO houses (owner_id, address, region, district, town, size, capacity, photos, furnished, for_rent, rent_amount, phone_number)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    connection.query(sql, [
        req.user.id, address, region, district, town, size, capacity, JSON.stringify(photos), furnished, for_rent, rent_amount, phone_number
    ], (err, results) => {
        if (err) {
            console.error('Error adding house listing:', err);
            return res.status(500).json({ error: 'Failed to add house listing' });
        }
        res.status(201).json({ message: 'House added successfully', houseId: results.insertId });
    });
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
