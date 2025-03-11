const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const multer = require('multer');
const fs = require('fs');

// ✅ Initialize Express App
const app = express();
const PORT = 3000;

// ✅ Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('views')); // Serve static HTML
app.use('/uploads', express.static('uploads')); // Serve uploaded files

// ✅ Secret key for JWT
const SECRET_KEY = 'supersecretkey';

// ✅ MySQL Connection Config
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '13108375007',         
  database: 'mydatabase'
});

// ✅ Connect to MySQL
db.connect((err) => {
  if (err) {
    console.error('❌ MySQL connection failed:', err);
    return;
  }
  console.log('✅ Connected to MySQL Database');
});

// ✅ Multer Setup for File Uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = './uploads';
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir);
    }
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});
const upload = multer({ storage });

// -------------------- ROUTES -------------------- //

// ✅ Serve Pages
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});
app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'register.html'));
});
app.get('/user', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'user.html'));
});
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

// ✅ User Registration
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields are required!' });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
    db.query(query, [name, email, hashedPassword], (err) => {
      if (err) return res.status(500).json({ error: 'User registration failed!' });
      res.json({ message: 'User registered successfully!' });
    });
  } catch (error) {
    res.status(500).json({ error: 'Something went wrong!' });
  }
});

// ✅ User Login
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required!' });

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err || results.length === 0) return res.status(400).json({ error: 'User not found!' });
    
    const user = results[0];
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).json({ error: 'Invalid password!' });

    const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ message: 'Login successful!', token });
  });
});

// ✅ Upload Paper (Protected)
app.post('/upload-paper', verifyToken, upload.single('paper'), (req, res) => {
    console.log('REQ.USER:', req.user);
    console.log('REQ.BODY:', req.body);
    console.log('REQ.FILE:', req.file);
  
    const userId = req.user.id;
    const { title, description, abstract } = req.body;
    const paperDescription = description || abstract;
    const filePath = req.file ? req.file.path : null;
  
    if (!filePath) {
      console.error('No file uploaded');
      return res.status(400).json({ error: 'No file uploaded!' });
    }
  
    const query = 'INSERT INTO papers (user_id, title, description, file_path, status) VALUES (?, ?, ?, ?, ?)';
    db.query(query, [userId, title, paperDescription, filePath, 'Submitted'], (err) => {
      if (err) {
        console.error('DB Insert Error:', err); // ✅ This will show the real problem
        return res.status(500).json({ error: 'Paper submission failed!' });
      }
      res.json({ message: 'Paper submitted successfully!' });
    });
  });

// ✅ Get User Papers (Protected)
app.get('/my-papers', verifyToken, (req, res) => {
    const userId = req.user.id;
  
    console.log('Fetching papers for user:', req.user); // ✅ This is safe
  
    const query = 'SELECT * FROM papers WHERE user_id = ?';
  
    db.query(query, [userId], (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Failed to fetch papers!' });
      }
  
      res.json(results);
    });
  });
  
// ===================== REVIEWER ROUTES ===================== //

// ✅ Reviewer Registration
app.post('/reviewer-register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields are required!' });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = 'INSERT INTO reviewers (name, email, password) VALUES (?, ?, ?)';
    db.query(query, [name, email, hashedPassword], (err) => {
      if (err) return res.status(500).json({ error: 'Reviewer registration failed!' });
      res.json({ message: 'Reviewer registered successfully!' });
    });
  } catch (error) {
    res.status(500).json({ error: 'Something went wrong!' });
  }
});

// ✅ Reviewer Login
app.post('/reviewer-login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required!' });

  const query = 'SELECT * FROM reviewers WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err || results.length === 0) return res.status(400).json({ error: 'Reviewer not found!' });

    const reviewer = results[0];
    const isValid = await bcrypt.compare(password, reviewer.password);
    if (!isValid) return res.status(401).json({ error: 'Invalid password!' });

    const token = jwt.sign({ id: reviewer.id, email: reviewer.email }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ message: 'Reviewer login successful!', token });
  });
});

// ✅ Get Papers for Review (Protected)
app.get('/review-papers', verifyToken, (req, res) => {
  const query = 'SELECT * FROM papers WHERE status = "Submitted"';
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch papers!' });
    res.json(results);
  });
});

// ✅ Submit Review (Protected)
app.post('/submit-review', verifyToken, (req, res) => {
    const reviewerId = req.user.id;
    const { paperId, reviewText, score, status } = req.body;
  
    console.log('Incoming Review:', { paperId, reviewText, score, status });
  
    // Validate inputs
    if (
      typeof paperId === 'undefined' ||
      typeof reviewText !== 'string' || reviewText.trim() === '' ||
      typeof score === 'undefined' ||
      typeof status !== 'string' || status.trim() === ''
    ) {
      console.log('Validation failed due to missing fields.');
      return res.status(400).json({ error: 'All fields are required!' });
    }
  
    const reviewQuery = `
      INSERT INTO reviews (reviewer_id, paper_id, comments, score, status)
      VALUES (?, ?, ?, ?, ?)
    `;
  
    db.query(reviewQuery, [reviewerId, paperId, reviewText.trim(), score, status.trim()], (err, result) => {
      if (err) {
        console.error('Review Insert Error:', err);
        return res.status(500).json({ error: 'Failed to submit review!' });
      }
  
      const paperUpdateQuery = `
        UPDATE papers SET status = ? WHERE id = ?
      `;
  
      db.query(paperUpdateQuery, [status.trim(), paperId], (err2, result2) => {
        if (err2) {
          console.error('Paper Status Update Error:', err2);
          return res.status(500).json({ error: 'Failed to update paper status!' });
        }
  
        res.json({ message: 'Review submitted and paper status updated!' });
      });
    });
  });

  
  

// ===================== MIDDLEWARE ===================== //

// ✅ JWT Verification
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

// ✅ Start Server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
