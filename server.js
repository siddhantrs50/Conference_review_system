const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const multer = require('multer');
const fs = require('fs');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(bodyParser.json());
app.use(express.static('views'));
app.use('/uploads', express.static('uploads'));

const SECRET_KEY = 'supersecretkey';

// ✅ MySQL connection
const db = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '13108375007',
  database: 'mydatabase',
  waitForConnections: true,
  connectionLimit: 10,  // Number of connections (tweakable)
  queueLimit: 0         // Unlimited queue
});

db.getConnection((err, connection) => {
  if (err) {
    console.error('❌ MySQL connection failed:', err);
    return;
  }
  console.log('✅ Connected to MySQL Database');
  connection.release(); // ✅ Release connection back to pool
});


// ✅ Multer file upload setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = './uploads';
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});
const upload = multer({ storage });

/* ==================================================
   PAGE ROUTES
================================================== */
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'views', 'index.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'views', 'register.html')));
app.get('/user', (req, res) => res.sendFile(path.join(__dirname, 'views', 'user.html')));
app.get('/reviewer-register', (req, res) => res.sendFile(path.join(__dirname, 'views', 'reviewer-register.html')));
app.get('/reviewer-login', (req, res) => res.sendFile(path.join(__dirname, 'views', 'reviewer-login.html')));
app.get('/reviewer-dashboard', (req, res) => res.sendFile(path.join(__dirname, 'views', 'reviewer-dashboard.html')));
app.get('/admin-register', (req, res) => res.sendFile(path.join(__dirname, 'views', 'admin-register.html')));
app.get('/admin-login', (req, res) => res.sendFile(path.join(__dirname, 'views', 'admin-login.html')));
app.get('/admin-dashboard', (req, res) => res.sendFile(path.join(__dirname, 'views', 'admin-dashboard.html')));

/* ==================================================
   USER ROUTES (RESEARCHERS)
================================================== */
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'All fields are required!' });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      [name, email, hashedPassword],
      err => {
        console.log(err);
        if (err) return res.status(500).json({ error: 'User registration failed!' });
        res.json({ message: 'User registered successfully!' });
      });
  } catch (error) {
    res.status(500).json({ error: 'Something went wrong!' });
  }
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err || results.length === 0)
      return res.status(400).json({ error: 'User not found!' });

    const user = results[0];
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid)
      return res.status(401).json({ error: 'Invalid password!' });

    const token = jwt.sign({ id: user.id, email: user.email, role: 'user' }, SECRET_KEY);
    res.json({ message: 'Login successful!', token });
  });
});

app.post('/upload-paper', verifyToken, upload.single('paper'), (req, res) => {
  const userId = req.user.id;
  const { title, description, abstract } = req.body;
  const paperDescription = description || abstract;
  if (!req.file)
    return res.status(400).json({ error: 'No file uploaded!' });

  const filePath = req.file.path;
  const query = 'INSERT INTO papers (user_id, title, description, file_path, status, created_at) VALUES (?, ?, ?, ?, ?, NOW())';
  db.query(query, [userId, title, paperDescription, filePath, 'Submitted'], err => {
    if (err) return res.status(500).json({ error: 'Paper submission failed!' });
    res.json({ message: 'Paper submitted successfully!' });
  });
});

app.get('/my-papers', verifyToken, (req, res) => {
  const userId = req.user.id;

  const query = `
    SELECT 
      p.*,
      r.score,
      r.status AS reviewStatus,
      r.user_comment,
      rv.name AS reviewerName,
      r.created_at AS review_created_at
    FROM papers p
    LEFT JOIN reviews r ON r.id = (
      SELECT rev_inner.id
      FROM reviews rev_inner
      WHERE rev_inner.paper_id = p.id
      ORDER BY rev_inner.created_at DESC
      LIMIT 1
    )
    LEFT JOIN reviewers rv ON r.reviewer_id = rv.id
    WHERE p.user_id = ?
    ORDER BY p.created_at DESC
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('❌ Error in /my-papers:', err);
      return res.status(500).json({ error: 'Failed to fetch papers!' });
    }

    // Convert review_created_at to ISO string if exists
    const formattedResults = results.map(row => ({
      ...row,
      review_created_at: row.review_created_at
        ? new Date(row.review_created_at).toISOString()
        : null
    }));

    res.json(formattedResults);
  });
});






app.get('/profile', verifyToken, (req, res) => {
  const userId = req.user.id;
  db.query('SELECT name, email FROM users WHERE id = ?', [userId], (err, results) => {
    if (err || results.length === 0)
      return res.status(404).json({ error: 'User not found!' });

    const user = results[0];
    res.json({ username: user.name, email: user.email, role: 'Author' });
  });
});

/* ==================================================
   REVIEWER ROUTES
================================================== */
app.post('/reviewer-register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'All fields are required!' });

  const hashedPassword = await bcrypt.hash(password, 10);
  db.query('INSERT INTO reviewers (name, email, password) VALUES (?, ?, ?)',
    [name, email, hashedPassword],
    err => {
      if (err) return res.status(500).json({ error: 'Reviewer registration failed!' });
      res.json({ message: 'Reviewer registered successfully!' });
    });
});

app.post('/reviewer-login', (req, res) => {
  const { email, password } = req.body;
  db.query('SELECT * FROM reviewers WHERE email = ?', [email], async (err, results) => {
    if (err || results.length === 0)
      return res.status(400).json({ error: 'Reviewer not found!' });

    const reviewer = results[0];
    const isValid = await bcrypt.compare(password, reviewer.password);
    if (!isValid)
      return res.status(401).json({ error: 'Invalid password!' });

    const token = jwt.sign({ id: reviewer.id, email: reviewer.email, role: 'reviewer' }, SECRET_KEY);
    res.json({ message: 'Reviewer login successful!', token });
  });
});

app.get('/review-papers', verifyToken, (req, res) => {
  const reviewerId = req.user.id;

  const query = `
    SELECT p.*
    FROM papers p
    JOIN paper_reviewers pr ON p.id = pr.paper_id
    WHERE pr.reviewer_id = ?
    AND (p.status = 'Submitted' OR p.status = 'Resubmitted')
  `;

  db.query(query, [reviewerId], (err, results) => {
    if (err) {
      console.error('❌ Failed to fetch assigned papers:', err);
      return res.status(500).json({ error: 'Failed to fetch assigned papers!' });
    }

    res.json(results);
  });
});


app.post('/submit-review', verifyToken, (req, res) => {
  const reviewerId = req.user.id;
  const { paperId, userComment, adminComment, score, status } = req.body;

  if (!paperId || !userComment || !adminComment || !score || !status) {
    return res.status(400).json({ error: 'All fields are required!' });
  }

  const reviewQuery = `
    INSERT INTO reviews (reviewer_id, paper_id, user_comment, admin_comment, score, status)
    VALUES (?, ?, ?, ?, ?, ?)
  `;

  db.query(reviewQuery, [reviewerId, paperId, userComment, adminComment, score, status], (err) => {
    if (err) return res.status(500).json({ error: 'Failed to submit review!' });

    db.query('UPDATE papers SET status = ? WHERE id = ?', [status, paperId], (err2) => {
      if (err2) return res.status(500).json({ error: 'Failed to update paper status!' });
      res.json({ message: 'Review submitted and paper status updated!' });
    });
  });
});

app.get('/reviewer-profile', verifyToken, (req, res) => {
  const reviewerId = req.user.id;
  db.query('SELECT name, email FROM reviewers WHERE id = ?', [reviewerId], (err, results) => {
    if (err || results.length === 0)
      return res.status(404).json({ error: 'Reviewer not found!' });

    res.json({ name: results[0].name, email: results[0].email, role: 'Reviewer' });
  });
});

app.get('/reviewer-reviewed-papers', verifyToken, (req, res) => {
  const reviewerId = req.user.id;

  const query = `
    SELECT
      p.title,
      p.file_path,
      r.score,
      r.status,
      r.user_comment,
      r.admin_comment,
      r.created_at AS review_created_at
    FROM reviews r
    JOIN papers p ON r.paper_id = p.id
    WHERE r.reviewer_id = ?
  `;

  db.query(query, [reviewerId], (err, results) => {
    if (err) {
      console.error('❌ Failed to fetch reviewed papers:', err);
      return res.status(500).json({ error: 'Failed to fetch reviewed papers!' });
    }

    res.json(results);
  });
});


/* ==================================================
   ADMIN ROUTES
================================================== */
app.post('/admin-register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'All fields are required!' });

  const hashedPassword = await bcrypt.hash(password, 10);
  db.query('INSERT INTO admins (name, email, password) VALUES (?, ?, ?)',
    [name, email, hashedPassword],
    err => {
      if (err) return res.status(500).json({ error: 'Admin registration failed!' });
      res.json({ message: 'Admin registered successfully!' });
    });
});

app.post('/admin-login', (req, res) => {
  const { email, password } = req.body;
  db.query('SELECT * FROM admins WHERE email = ?', [email], async (err, results) => {
    if (err || results.length === 0)
      return res.status(400).json({ error: 'Admin not found!' });

    const admin = results[0];
    const isValid = await bcrypt.compare(password, admin.password);
    if (!isValid)
      return res.status(401).json({ error: 'Invalid password!' });

    const token = jwt.sign({ id: admin.id, email: admin.email, role: 'admin' }, SECRET_KEY);
    res.json({ message: 'Admin login successful!', token });
  });
});

app.get('/admin-profile', verifyAdmin, (req, res) => {
  db.query('SELECT name, email FROM admins WHERE id = ?', [req.admin.id], (err, results) => {
    if (err || results.length === 0)
      return res.status(404).json({ error: 'Admin not found!' });

    res.json({ name: results[0].name, email: results[0].email });
  });
});

app.get('/admin-papers', verifyAdmin, (req, res) => {
  const query = `
    SELECT p.*
    FROM papers p
    LEFT JOIN paper_reviewers pr ON p.id = pr.paper_id
    WHERE pr.paper_id IS NULL
  `;

  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch unassigned papers!' });
    res.json(results);
  });
});

app.get('/admin-assigned-papers', verifyAdmin, (req, res) => {
  const query = `
    SELECT
      p.id,
      p.title,
      p.status,
      p.file_path,

      (
        SELECT MAX(pr_inner.assigned_on)
        FROM paper_reviewers pr_inner
        WHERE pr_inner.paper_id = p.id
      ) AS assigned_on,

      (
        SELECT GROUP_CONCAT(DISTINCT r.name)
        FROM paper_reviewers pr2
        JOIN reviewers r ON pr2.reviewer_id = r.id
        WHERE pr2.paper_id = p.id
      ) AS reviewerNames,

      (
        SELECT rev_inner.id
        FROM reviews rev_inner
        WHERE rev_inner.paper_id = p.id
        ORDER BY rev_inner.created_at DESC
        LIMIT 1
      ) AS reviewId,

      (
        SELECT rev_inner.score
        FROM reviews rev_inner
        WHERE rev_inner.paper_id = p.id
        ORDER BY rev_inner.created_at DESC
        LIMIT 1
      ) AS score,

      (
        SELECT rev_inner.status
        FROM reviews rev_inner
        WHERE rev_inner.paper_id = p.id
        ORDER BY rev_inner.created_at DESC
        LIMIT 1
      ) AS reviewStatus,

      (
        SELECT rev_inner.user_comment
        FROM reviews rev_inner
        WHERE rev_inner.paper_id = p.id
        ORDER BY rev_inner.created_at DESC
        LIMIT 1
      ) AS user_comment

    FROM papers p
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error('❌ Error in admin-assigned-papers:', err);
      return res.status(500).json({ error: 'Failed to fetch assigned papers!' });
    }

    console.log('✅ admin-assigned-papers results:', results);
    res.json(results);
  });
});





app.get('/admin-reviewed-papers', verifyAdmin, (req, res) => {
  const query = `
    SELECT
      r.id AS reviewId,
      p.title,
      p.file_path,
      r.score,
      r.status,
      r.user_comment,
      r.admin_comment,
      rv.name AS reviewerName
    FROM reviews r
    JOIN papers p ON r.paper_id = p.id
    JOIN reviewers rv ON r.reviewer_id = rv.id
  `;

  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch reviewed papers!' });
    res.json(results);
  });
});

app.post('/admin-assign-reviewer', verifyAdmin, (req, res) => {
  const { paperId, reviewerId } = req.body;
  if (!paperId || !reviewerId)
    return res.status(400).json({ error: 'Both paperId and reviewerId are required!' });

  db.query('INSERT INTO paper_reviewers (paper_id, reviewer_id, assigned_on ) VALUES (?, ?, NOW())',
    [paperId, reviewerId], (err) => {
      console.log(err);
      if (err) return res.status(500).json({ error: 'Failed to assign reviewer!' });
      res.json({ message: 'Reviewer assigned successfully!' });
    });
});

app.put('/admin-overwrite-review', verifyAdmin, (req, res) => {
  const { reviewId, score, status, user_comment } = req.body;

  if (!reviewId || !score || !status || !user_comment) {
    return res.status(400).json({ error: 'All fields are required!' });
  }

  db.query(`
    UPDATE reviews
    SET score = ?, status = ?, user_comment = ?
    WHERE id = ?
  `, [score, status, user_comment, reviewId], (err) => {
    if (err) return res.status(500).json({ error: 'Failed to overwrite review!' });
    res.json({ message: 'Review successfully overwritten!' });
  });
});

app.get('/admin-reviewers', verifyAdmin, (req, res) => {
  db.query('SELECT id, name, email FROM reviewers', (err, results) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch reviewers!' });
    res.json(results);
  });
});

/* ==================================================
   USER REVIEWED & UNREVIEWED PAPERS ROUTES
================================================== */

// ✅ Reviewed Papers for User
app.get('/user-reviewed-papers', verifyToken, (req, res) => {
  const userId = req.user.id;

  const query = `
    SELECT
      p.id,
      p.title,
      p.file_path,
      r.score,
      r.status,
      r.user_comment,
      r.admin_comment,
      rv.name AS reviewerName
    FROM papers p
    JOIN reviews r ON p.id = r.paper_id
    JOIN reviewers rv ON r.reviewer_id = rv.id
    WHERE p.user_id = ?
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Error fetching reviewed papers:', err);
      return res.status(500).json({ error: 'Failed to fetch reviewed papers!' });
    }

    res.json(results);
  });
});

// ✅ Unreviewed Papers for User
app.get('/user-unreviewed-papers', verifyToken, (req, res) => {
  const userId = req.user.id;

  const query = `
    SELECT
      p.id,
      p.title,
      p.file_path,
      p.status
    FROM papers p
    WHERE p.user_id = ?
    AND p.id NOT IN (
      SELECT paper_id FROM reviews
    )
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Error fetching unreviewed papers:', err);
      return res.status(500).json({ error: 'Failed to fetch unreviewed papers!' });
    }

    res.json(results);
  });
});

app.put('/update-paper/:paperId', verifyToken, upload.single('paper'), (req, res) => {
  const userId = req.user.id;
  const paperId = req.params.paperId;
  const { description, title } = req.body;

  console.log("➡️ Incoming request...");
  console.log("Paper ID:", paperId);
  console.log("User ID:", userId);
  console.log("Title:", title);
  console.log("Description:", description);
  console.log("File object:", req.file);

  if (!req.file) {
    console.log("❌ No file uploaded!");
    return res.status(400).json({ error: 'No file uploaded!' });
  }

  const filePath = req.file.path;

  // ✅ Check if the paper was rejected AND find the review date
  const checkQuery = `
    SELECT p.*, r.created_at AS review_created_at
    FROM papers p
    JOIN reviews r ON p.id = r.paper_id
    WHERE p.id = ? AND p.user_id = ? AND p.status = 'Rejected'
    ORDER BY r.created_at DESC
    LIMIT 1
  `;

  db.query(checkQuery, [paperId, userId], (err, results) => {
    if (err) {
      console.error('❌ Error fetching paper:', err);
      return res.status(500).json({ error: 'Server error!' });
    }

    console.log("✅ Paper check result:", results);

    if (results.length === 0) {
      console.log("❌ No matching paper found or not rejected.");
      return res.status(403).json({ error: 'Paper not found or cannot be updated!' });
    }

    const reviewCreatedAt = new Date(results[0].review_created_at);
    const currentDate = new Date();
    const diffTime = currentDate - reviewCreatedAt;
    const diffDays = diffTime / (1000 * 60 * 60 * 24);

    console.log(`📅 Review date: ${reviewCreatedAt}`);
    console.log(`📅 Current date: ${currentDate}`);
    console.log(`⏳ Days since review: ${diffDays}`);

    if (diffDays > 7) {
      console.log("❌ Update window expired.");
      return res.status(403).json({ error: 'Update window expired! You can only update within 7 days after review.' });
    }

    const updateQuery = `
      UPDATE papers 
      SET title = ?, description = ?, file_path = ?, status = 'Submitted', created_at = NOW()
      WHERE id = ? AND user_id = ?
    `;

    db.query(updateQuery, [title, description, filePath, paperId, userId], (updateErr) => {
      if (updateErr) {
        console.error('❌ Error updating paper:', updateErr);
        return res.status(500).json({ error: 'Failed to update paper!' });
      }

      console.log("✅ Paper updated and resubmitted successfully!");
      res.json({ message: 'Paper updated and resubmitted successfully!' });
    });
  });
});



/* ==================================================
   MIDDLEWARE
================================================== */
function verifyToken(req, res, next) {
  const bearerHeader = req.headers['authorization'];
  if (!bearerHeader)
    return res.status(403).json({ error: 'Authorization token missing!' });

  const token = bearerHeader.split(' ')[1];
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err)
      return res.status(401).json({ error: 'Invalid or expired token!' });
    req.user = decoded;
    next();
  });
}

function verifyAdmin(req, res, next) {
  const bearerHeader = req.headers['authorization'];
  if (!bearerHeader)
    return res.status(403).json({ error: 'Authorization token missing!' });

  const token = bearerHeader.split(' ')[1];
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err || decoded.role !== 'admin')
      return res.status(401).json({ error: 'Unauthorized admin!' });
    req.admin = decoded;
    next();
  });
}

/* ==================================================
   START SERVER
================================================== */
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
