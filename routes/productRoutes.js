const express = require('express');
const router = express.Router();
const Product = require('../models/Products');
const User = require('../models/User');
const jwt = require('jsonwebtoken');

// Middleware to verify token for any logged-in user
const auth = (req, res, next) => {
  const token = req.header('x-auth-token');
  if (!token) return res.status(401).json({ msg: 'No token, authorization denied' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Token is not valid' });
  }
};

// Middleware to verify if user is admin
const adminAuth = async (req, res, next) => {
  const token = req.header('x-auth-token');
  if (!token) return res.status(401).json({ msg: 'No token, authorization denied' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;

    // Check if user is an admin
    const user = await User.findById(decoded.id); // Use `decoded.id` to fetch the user
    if (!user || user.admin !== 'yes') {
      return res.status(403).json({ msg: 'Access denied' });
    }

    next();
  } catch (err) {
    res.status(401).json({ msg: 'Token is not valid' });
  }
};

// Add product (admin only)
router.post('/add', adminAuth, async (req, res) => {
  const { name, description, price, imageUrl } = req.body;

  try {
    if (!name || !description || !price || !imageUrl) {
      return res.status(400).json({ msg: 'Please enter all fields' });
    }

    const newProduct = new Product({
      name,
      description,
      price,
      imageUrl
    });

    await newProduct.save();
    res.status(201).json(newProduct);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ msg: 'Server Error' });
  }
});

// Get all products (any logged-in user)
router.get('/', auth, async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ msg: 'Server Error' });
  }
});

module.exports = router;
