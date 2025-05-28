const express = require('express');
const path = require('path');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();
const port = 3001;

// Middleware to parse request body
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Set up MySQL database connection
const db = mysql.createConnection({
  host: 'localhost',  // ใช้ 'localhost' ถ้าติดตั้ง MySQL บนเครื่องเดียวกัน
  user: 'root',       // ชื่อผู้ใช้ของ MySQL
  password: 'Zaapoopo@0000', // รหัสผ่านของ MySQL
  database: 'expense_tracker', // ชื่อฐานข้อมูล
});

// Connect to MySQL database
db.connect((err) => {
  if (err) {
    console.error('Could not connect to the database:', err);
    return;
  }
  console.log('Connected to the database');
});

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization') && req.header('Authorization').split(' ')[1]; // Get token from Bearer scheme
  if (!token) {
    return res.status(403).json({ message: 'Token not found' });
  }

  jwt.verify(token, 'your-secret-key', (err, user) => {
    if (err) {
      console.error('Token verification error:', err); // Log error
      return res.status(403).json({ message: 'Could not verify token' });
    }
    req.user = user;
    next();
  });
};

// Route for user registration (signup)
app.post('/api/register', (req, res) => {
  const { username, email, password } = req.body;

  // Hash the password
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      return res.status(500).json({ message: 'Error hashing the password' });
    }

    // SQL query to insert the user data
    const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
    db.query(query, [username, email, hashedPassword], (err, result) => {
      if (err) {
        return res.status(500).json({ message: 'Error registering the user', error: err });
      }
      res.status(201).json({ message: 'User registered successfully' });
    });
  });
});

// Route for user login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  // SQL query to get the user data
  const query = 'SELECT * FROM users WHERE username = ?';
  db.query(query, [username], (err, results) => {
    if (err || results.length === 0) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    const user = results[0];
    // Compare the provided password with the hashed password in the database
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err || !isMatch) {
        return res.status(401).json({ message: 'Invalid username or password' });
      }

      // Generate JWT token with extended expiration time
      const token = jwt.sign({ id: user.id, username: user.username }, 'your-secret-key', { expiresIn: '24h' });

      res.json({ message: 'Login successful', token });
    });
  });
});

// Route to refresh token
app.post('/api/refresh-token', authenticateToken, (req, res) => {
  const user = req.user;

  // Generate a new token with the same payload
  const newToken = jwt.sign({ id: user.id, username: user.username }, 'your-secret-key', { expiresIn: '24h' });

  res.json({ message: 'Token refreshed', token: newToken });
});

// Route to add a transaction (requires authentication)
app.post('/api/transactions', authenticateToken, (req, res) => {
  const { name, amount, category, type, date } = req.body;

  if (!name || !amount || !category || !type || !date) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  const transaction = {
    user_id: req.user.id, // ใช้ user_id จาก token
    name,
    amount,
    category,
    type,
    date
  };

  const query = 'INSERT INTO transactions (user_id, name, amount, category, type, date) VALUES (?, ?, ?, ?, ?, ?)';
  db.query(query, [transaction.user_id, transaction.name, transaction.amount, transaction.category, transaction.type, transaction.date], (err, result) => {
    if (err) {
      console.error('Error saving transaction:', err);
      return res.status(500).json({ message: 'An error occurred while saving the transaction' });
    }
    return res.status(201).json({ message: 'Transaction added successfully', data: result });
  });
});

// Route to get transactions for the user with optional filters (requires authentication)
app.get('/api/transactions', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const { category, type, startDate, endDate } = req.query; // รับข้อมูลจาก query string

  // SQL query with optional filters
  let query = 'SELECT * FROM transactions WHERE user_id = ?';
  let queryParams = [userId];

  // Filter by category if provided
  if (category && category !== 'all') {
    query += ' AND category = ?';
    queryParams.push(category);
  }

  // Filter by type if provided
  if (type && type !== 'all') {
    query += ' AND type = ?';
    queryParams.push(type);
  }

  // Filter by date range if provided (startDate and endDate)
  if (startDate) {
    query += ' AND date >= ?';
    queryParams.push(startDate);
  }

  if (endDate) {
    query += ' AND date <= ?';
    queryParams.push(endDate);
  }

  query += ' ORDER BY date DESC';

  db.query(query, queryParams, (err, results) => {
    if (err) {
      console.error('Error fetching transactions:', err);
      return res.status(500).json({ message: 'Error fetching transactions', error: err });
    }
    res.json(results);
  });
});

// Route to get total income and expenses for the user (requires authentication)
app.get('/api/summary', authenticateToken, (req, res) => {
  const userId = req.user.id;

  const query = `
    SELECT
      SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END) AS total_income,
      SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END) AS total_expense
    FROM transactions
    WHERE user_id = ?
  `;
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Error fetching summary:', err);
      return res.status(500).json({ message: 'Error fetching summary', error: err });
    }
    const summary = results[0];
    res.json({
      total_income: summary.total_income || 0,
      total_expense: summary.total_expense || 0
    });
  });
});

// Route to delete a transaction (requires authentication)
app.delete('/api/transactions/:id', authenticateToken, (req, res) => {
  const { id } = req.params;

  const query = 'DELETE FROM transactions WHERE id = ? AND user_id = ?';
  db.query(query, [id, req.user.id], (err, result) => {
    if (err) {
      return res.status(500).json({ message: 'Error deleting transaction', error: err });
    }
    if (result.affectedRows > 0) {
      res.json({ message: 'Transaction deleted successfully' });
    } else {
      res.status(404).json({ message: 'Transaction not found' });
    }
  });
});

// Route to get transaction data for charts (requires authentication)
app.get('/api/chart-data', authenticateToken, (req, res) => {
  const userId = req.user.id;

  const query = `
    SELECT category, SUM(amount) as total 
    FROM transactions 
    WHERE user_id = ? AND type = 'expense'
    GROUP BY category
    ORDER BY category ASC
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Error fetching chart data:', err);
      return res.status(500).json({ message: 'Error fetching chart data', error: err });
    }

    const labels = results.map(item => item.category);
    const data = results.map(item => item.total);

    res.json({ labels, data });
  });
});


app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
