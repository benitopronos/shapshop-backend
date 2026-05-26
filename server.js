const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const stripe = require('stripe')('sk_test_51TYhb8LF49m2VRjVUhHit7FsMA3cVg589eA6qLhgLu2mDyNzASo1BclcW9Ir4rBriIaOL2YmTTnjWe5Apyy98i7P001zidhgJe');

// ══ FIREBASE SETUP ══
const serviceAccount = require('./firebase-key.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://shap-shop-beni.firebaseio.com"
});

const db = admin.firestore();
const auth = admin.auth();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'shap-shop-beni-secret-key-change-in-production';

// ══ MIDDLEWARE ══
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:8080', 'https://shapshop.netlify.app'],
  credentials: true
}));
app.use(express.json());

// Logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// Error handler middleware
const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ══ AUTH MIDDLEWARE ══
const verifyToken = async (req, res, next) => {
  try {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    req.userEmail = decoded.email;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token', details: err.message });
  }
};

// ══ AUTHENTICATION ROUTES ══

// Signup
app.post('/api/auth/signup', asyncHandler(async (req, res) => {
  const { email, password, name, phone } = req.body;
  
  // Validation
  if (!email || !password || !name || !phone) {
    return res.status(400).json({ error: 'All fields required' });
  }
  
  // Vérifier si l'email existe
  const userSnapshot = await db.collection('users').where('email', '==', email).get();
  if (!userSnapshot.empty) {
    return res.status(400).json({ error: 'Email already exists' });
  }
  
  // Hash password
  const hashedPassword = await bcrypt.hash(password, 10);
  
  // Créer l'utilisateur
  const userId = `user_${Date.now()}`;
  await db.collection('users').doc(userId).set({
    id: userId,
    email,
    password: hashedPassword,
    name,
    phone,
    role: 'customer',
    created: admin.firestore.FieldValue.serverTimestamp(),
    status: 'active'
  });
  
  // Créer JWT token
  const token = jwt.sign({ id: userId, email }, JWT_SECRET, { expiresIn: '30d' });
  
  res.status(201).json({
    message: 'User created successfully',
    token,
    user: { id: userId, email, name, phone }
  });
}));

// Login
app.post('/api/auth/login', asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  
  // Trouver l'utilisateur
  const userSnapshot = await db.collection('users').where('email', '==', email).get();
  if (userSnapshot.empty) {
    return res.status(400).json({ error: 'User not found' });
  }
  
  const userData = userSnapshot.docs[0].data();
  const userId = userSnapshot.docs[0].id;
  
  // Vérifier le mot de passe
  const isPasswordValid = await bcrypt.compare(password, userData.password);
  if (!isPasswordValid) {
    return res.status(400).json({ error: 'Invalid password' });
  }
  
  // Créer JWT token
  const token = jwt.sign({ id: userId, email }, JWT_SECRET, { expiresIn: '30d' });
  
  res.json({
    message: 'Login successful',
    token,
    user: {
      id: userId,
      email: userData.email,
      name: userData.name,
      phone: userData.phone,
      role: userData.role
    }
  });
}));

// Get profile
app.get('/api/auth/profile', verifyToken, asyncHandler(async (req, res) => {
  const userDoc = await db.collection('users').doc(req.userId).get();
  if (!userDoc.exists) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  const userData = userDoc.data();
  res.json({
    user: {
      id: req.userId,
      email: userData.email,
      name: userData.name,
      phone: userData.phone,
      role: userData.role
    }
  });
}));

// ══ PRODUCTS ROUTES ══

// Get all products
app.get('/api/products', asyncHandler(async (req, res) => {
  const { category, search } = req.query;
  
  let query = db.collection('products');
  
  if (category && category !== 'Tous') {
    query = query.where('category', '==', category);
  }
  
  const snapshot = await query.get();
  let products = snapshot.docs.map(doc => ({
    id: doc.id,
    ...doc.data()
  }));
  
  if (search) {
    products = products.filter(p =>
      p.name.toLowerCase().includes(search.toLowerCase()) ||
      p.category.toLowerCase().includes(search.toLowerCase())
    );
  }
  
  res.json({ products });
}));

// Get product by ID
app.get('/api/products/:id', asyncHandler(async (req, res) => {
  const doc = await db.collection('products').doc(req.params.id).get();
  if (!doc.exists) {
    return res.status(404).json({ error: 'Product not found' });
  }
  
  res.json({
    product: {
      id: doc.id,
      ...doc.data()
    }
  });
}));

// Create product (Admin)
app.post('/api/products', verifyToken, asyncHandler(async (req, res) => {
  const user = await db.collection('users').doc(req.userId).get();
  if (user.data().role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  
  const { name, price, category, description, stock, image } = req.body;
  
  const productId = `prod_${Date.now()}`;
  await db.collection('products').doc(productId).set({
    id: productId,
    name,
    price,
    category,
    description,
    stock,
    image,
    rating: 5,
    reviews: 0,
    created: admin.firestore.FieldValue.serverTimestamp()
  });
  
  res.status(201).json({
    message: 'Product created',
    productId
  });
}));

// ══ CART ROUTES ══

// Add to cart
app.post('/api/cart/add', verifyToken, asyncHandler(async (req, res) => {
  const { productId, quantity } = req.body;
  
  const productDoc = await db.collection('products').doc(productId).get();
  if (!productDoc.exists) {
    return res.status(404).json({ error: 'Product not found' });
  }
  
  const cartId = `cart_${req.userId}`;
  const cartDoc = await db.collection('carts').doc(cartId).get();
  
  let cartItems = cartDoc.exists ? cartDoc.data().items || [] : [];
  
  const existingItem = cartItems.find(item => item.productId === productId);
  
  if (existingItem) {
    existingItem.quantity += quantity;
  } else {
    const productData = productDoc.data();
    cartItems.push({
      productId,
      name: productData.name,
      price: productData.price,
      quantity,
      image: productData.image
    });
  }
  
  await db.collection('carts').doc(cartId).set({
    userId: req.userId,
    items: cartItems,
    updated: admin.firestore.FieldValue.serverTimestamp()
  });
  
  res.json({ message: 'Added to cart', cart: cartItems });
}));

// Get cart
app.get('/api/cart', verifyToken, asyncHandler(async (req, res) => {
  const cartId = `cart_${req.userId}`;
  const cartDoc = await db.collection('carts').doc(cartId).get();
  
  const items = cartDoc.exists ? cartDoc.data().items || [] : [];
  const total = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
  
  res.json({ cart: items, total });
}));

// Clear cart
app.delete('/api/cart', verifyToken, asyncHandler(async (req, res) => {
  const cartId = `cart_${req.userId}`;
  await db.collection('carts').doc(cartId).delete();
  res.json({ message: 'Cart cleared' });
}));

// ══ ORDERS ROUTES ══

// Create order
app.post('/api/orders/create', verifyToken, asyncHandler(async (req, res) => {
  const { amount } = req.body;
  
  const cartId = `cart_${req.userId}`;
  const cartDoc = await db.collection('carts').doc(cartId).get();
  
  if (!cartDoc.exists || cartDoc.data().items.length === 0) {
    return res.status(400).json({ error: 'Cart is empty' });
  }
  
  const orderId = `order_${Date.now()}`;
  await db.collection('orders').doc(orderId).set({
    id: orderId,
    userId: req.userId,
    items: cartDoc.data().items,
    total: amount,
    status: 'pending',
    created: admin.firestore.FieldValue.serverTimestamp()
  });
  
  // Clear cart
  await db.collection('carts').doc(cartId).delete();
  
  res.json({
    message: 'Order created',
    orderId,
    amount
  });
}));

// Get user orders
app.get('/api/orders', verifyToken, asyncHandler(async (req, res) => {
  const ordersSnapshot = await db.collection('orders')
    .where('userId', '==', req.userId)
    .orderBy('created', 'desc')
    .get();
  
  const orders = ordersSnapshot.docs.map(doc => ({
    id: doc.id,
    ...doc.data()
  }));
  
  res.json({ orders });
}));

// ══ STRIPE PAYMENT ══

app.post('/api/payment/create-intent', verifyToken, asyncHandler(async (req, res) => {
  const { amount } = req.body;
  
  const paymentIntent = await stripe.paymentIntents.create({
    amount: Math.round(amount * 100),
    currency: 'eur',
    metadata: {
      userId: req.userId
    }
  });
  
  res.json({
    clientSecret: paymentIntent.client_secret,
    publishableKey: 'pk_test_51TYhb8LF49m2VRjVAGhL0aIZNv2KbGgja1hcweYTNsivTgnhKQmiWl6c41gZ7dznsMk2ffCevcP3yD9g41Z6Duue001l2IPKFw'
  });
}));

// ══ ADMIN ROUTES ══

// Dashboard stats
app.get('/api/admin/stats', verifyToken, asyncHandler(async (req, res) => {
  const user = await db.collection('users').doc(req.userId).get();
  if (user.data().role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  
  const usersSnapshot = await db.collection('users').get();
  const productsSnapshot = await db.collection('products').get();
  const ordersSnapshot = await db.collection('orders').get();
  
  const totalRevenue = ordersSnapshot.docs.reduce((sum, doc) => sum + doc.data().total, 0);
  
  res.json({
    stats: {
      totalUsers: usersSnapshot.size,
      totalProducts: productsSnapshot.size,
      totalOrders: ordersSnapshot.size,
      totalRevenue
    }
  });
}));

// ══ HEALTH CHECK ══
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    message: 'SHAP SHOP BENI Backend is running',
    timestamp: new Date(),
    firebase: 'Connected'
  });
});

// ══ ERROR HANDLER ══
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error'
  });
});

// ══ START SERVER ══
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
  });
}

module.exports = app;
