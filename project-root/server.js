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
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// Merchant Schema
const merchantSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  merchantName: { type: String, required: true },
  phoneNumber: { type: String, required: true },
  cropType: { type: String, required: true },
  priceRange: { type: Number, required: true },
  address: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const Merchant = mongoose.model('Merchant', merchantSchema);

// Authentication Middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Routes
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (await User.findOne({ email })) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ 
      token, 
      user: { 
        id: user._id, 
        name: user.name, 
        email: user.email
      } 
    });

  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ 
      token, 
      user: { 
        id: user._id, 
        name: user.name, 
        email: user.email
      } 
    });

  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Merchant Submission Route
app.post('/api/merchant', authenticate, async (req, res) => {
    try {
      const { merchantName, phoneNumber, cropType, priceRange, address } = req.body;
  
      // Validate all fields
      if (!merchantName || !phoneNumber || !cropType || !priceRange || !address) {
        return res.status(400).json({ error: 'All fields are required' });
      }
  
      // Create and save the document
      const merchantData = new Merchant({
        userId: req.userId,
        merchantName: merchantName.trim(), // Ensure no whitespace
        phoneNumber: phoneNumber.trim(),
        cropType: cropType.trim(),
        priceRange: parseFloat(priceRange),
        address: address.trim()
      });
  
      await merchantData.save();
      console.log('Saved Data (Full):', merchantData); // Debug: Log full saved data
      res.status(201).json({ message: 'Details saved successfully' });
    } catch (err) {
      console.error('Error saving merchant data:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

// Fetch Merchant Data Route
app.get('/api/merchant-data', authenticate, async (req, res) => {
  try {
    const merchantData = await Merchant.find({ userId: req.userId });
    console.log('Fetched Merchant Data:', merchantData); // Debug: Log fetched data
    res.json(merchantData);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Serve Frontend
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

app.get('/api/merchant-data', authenticate, async (req, res) => {
    try {
      const merchantData = await Merchant.find({ userId: req.userId });
      console.log('Fetched Merchant Data (Raw):', merchantData); // Debug: Log raw data
      res.json(merchantData);
    } catch (err) {
      res.status(500).json({ error: 'Server error' });
    }
  });

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));