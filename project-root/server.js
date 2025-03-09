require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();

// Configuration
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database Connection
mongoose.connect(process.env.DB_URI)
  .then(() => console.log('[Backend] Connected to MongoDB'))
  .catch(err => console.error('[Backend] MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// Merchant Schema
const merchantSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Optional for anonymous submissions
  publicName: { type: String, required: true }, // Display name instead of real name
  merchantName: { type: String, required: true },
  phoneNumber: { type: String, required: true },
  cropType: { type: String, required: true },
  priceRange: { type: Number, required: true },
  address: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const Merchant = mongoose.model('Merchant', merchantSchema);

// Enhanced Authentication Middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  console.log('[Backend] Received token:', token);

  if (!token) {
    console.log('[Backend] No token provided');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log('[Backend] Decoded token:', decoded);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    console.error('[Backend] Token verification error:', err);
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Routes

// Signup
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });

    if (await User.findOne({ email })) return res.status(400).json({ error: 'Email already exists' });

    const user = new User({
      name,
      email,
      password: await bcrypt.hash(password, 10)
    });
    await user.save();

    res.status(201).json({
      token: jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' })
    });
  } catch (err) {
    console.error('[Backend] Signup error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    res.json({
      token: jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' })
    });
  } catch (err) {
    console.error('[Backend] Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Merchant Submission
app.post('/api/merchant', authenticate, async (req, res) => {
  try {
    const { merchantName, phoneNumber, cropType, priceRange, address } = req.body;
    if (!merchantName || !phoneNumber || !cropType || !priceRange || !address) {
      return res.status(400).json({ error: 'All fields required' });
    }

    const merchant = new Merchant({
      userId: req.userId,
      publicName: merchantName, // Use merchantName as publicName
      merchantName,
      phoneNumber,
      cropType,
      priceRange: parseFloat(priceRange),
      address
    });
    await merchant.save();

    res.status(201).json({ message: 'Submission successful' });
  } catch (err) {
    console.error('[Backend] Merchant submission error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Fetch User-Specific Submissions (My Submissions)
app.get('/api/merchant-data', authenticate, async (req, res) => {
  try {
    console.log(`[Backend] Fetching data for user: ${req.userId}`);
    
    const merchantData = await Merchant.find({ userId: req.userId })
      .lean()
      .exec();

    console.log(`[Backend] Found ${merchantData.length} records`);
    res.json(merchantData);
  } catch (err) {
    console.error('[Backend] Database error:', err);
    res.status(500).json({ 
      error: 'Server error',
      details: err.message 
    });
  }
});

// Fetch All Submissions (Public Marketplace)
app.get('/api/public-submissions', async (req, res) => {
  try {
    const submissions = await Merchant.find().sort({ createdAt: -1 });
    res.json(submissions);
  } catch (err) {
    console.error('[Backend] Public submissions error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Serve Frontend Pages
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/submissions', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'submissions.html'));
});

app.get('/public-submissions', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'public-submissions.html'));
});

// Start the server
app.listen(PORT, () => console.log(`[Backend] Server running on port ${PORT}`));