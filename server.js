const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');

// ✅ Initialize Express App
const app = express();
const PORT = 3000;

// ✅ Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('views')); // To serve static HTML files from views folder

// ✅ Secret key for JWT (keep this safe in production)
const SECRET_KEY = 'supersecretkey';

// ✅ MySQL Connection Config
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '13108375007',         // Your MySQL password
  database: 'mydatabase'           // Your MySQL database name
});

// ✅ Connect to MySQL
db.connect((err) => {
  if (err) {
    console.error('❌ MySQL connection failed:', err);
    return;
  }
  console.log('✅ Connected to MySQL Database');
});

// -------------------- ROUTES -------------------- //

// ✅ Serve User Pages
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'register.html'));
});

app.get('/user', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'user.html'));
});

// ✅ Serve Reviewer Pages
app.get('/reviewer-register', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'reviewer-register.html'));
});

app.get('/reviewer-login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'reviewer-login.html'));
});

app.get('/reviewer-dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'reviewer-dashboard.html'));
});

// ===================== USER ROUTES ===================== //

// ✅ Register a new user
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'All fields are required!' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
    
    db.query(query, [name, email, hashedPassword], (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'User registration failed!' });
      }
      res.json({ message: 'User registered successfully!' });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong!' });
  }
});

// ✅ Login user
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required!' });
  }

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err) return res.status(500).json({ error: 'Database query error!' });
    if (results.length === 0) return res.status(400).json({ error: 'User not found!' });

    const user = results[0];
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid password!' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '1h' });

    res.json({ message: 'Login successful!', token });
  });
});

// ✅ Protected route for all users
app.get('/users', verifyToken, (req, res) => {
  const query = 'SELECT id, name, email FROM users';

  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Error fetching users!' });

    res.json(results);
  });
});

// ===================== REVIEWER ROUTES ===================== //

// ✅ Register a new reviewer
app.post('/reviewer-register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'All fields are required!' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = 'INSERT INTO reviewers (name, email, password) VALUES (?, ?, ?)';
    
    db.query(query, [name, email, hashedPassword], (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Reviewer registration failed!' });
      }
      res.json({ message: 'Reviewer registered successfully!' });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong!' });
  }
});

// ✅ Login reviewer
app.post('/reviewer-login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required!' });
  }

  const query = 'SELECT * FROM reviewers WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err) return res.status(500).json({ error: 'Database query error!' });
    if (results.length === 0) return res.status(400).json({ error: 'Reviewer not found!' });

    const reviewer = results[0];
    const isValidPassword = await bcrypt.compare(password, reviewer.password);

    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid password!' });
    }

    const token = jwt.sign({ id: reviewer.id, email: reviewer.email }, SECRET_KEY, { expiresIn: '1h' });

    res.json({ message: 'Reviewer login successful!', token });
  });
});

// ✅ Protected route to get all reviewers
app.get('/reviewers', verifyToken, (req, res) => {
  const query = 'SELECT id, name, email FROM reviewers';

  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Error fetching reviewers!' });

    res.json(results);
  });
});

// ===================== MIDDLEWARE ===================== //

// ✅ Middleware to verify JWT token
function verifyToken(req, res, next) {
  const bearerHeader = req.headers['authorization'];
  if (!bearerHeader) return res.status(403).json({ error: 'Authorization token missing!' });

  const token = bearerHeader.split(' ')[1];
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid or expired token!' });

    req.user = decoded;
    next();
  });
}

// ✅ Start the server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
