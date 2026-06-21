const express = require('express');
const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cloudinary = require('cloudinary').v2;
const nodemailer = require('nodemailer');
const { OpenAI } = require('openai');
const axios = require('axios');
const path = require('path');
require('dotenv').config();

const app = express();

// =============================================
// 🔥 FIREBASE INITIALIZATION - FIXED
// =============================================
let db;

// التحقق إذا كان Firebase مهيأ مسبقاً
if (!admin.apps.length) {
  try {
    const serviceAccount = JSON.parse(process.env.FIREBASE_CONFIG);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    console.log('✅ Firebase initialized successfully');
  } catch (error) {
    console.error('❌ Firebase initialization error:', error.message);
    process.exit(1);
  }
} else {
  console.log('ℹ️ Firebase already initialized, using existing app');
}

db = admin.firestore();

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Configure OpenAI
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// Configure Email
const transporter = nodemailer.createTransporter({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP'
});
app.use('/api/', limiter);

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Admin Middleware
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Helper Functions
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

const sendEmail = async (to, subject, html) => {
  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM,
      to,
      subject,
      html
    });
    return true;
  } catch (error) {
    console.error('Email error:', error);
    return false;
  }
};

const sendTelegram = async (message) => {
  try {
    await axios.post(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
      chat_id: process.env.TELEGRAM_CHAT_ID,
      text: message,
      parse_mode: 'HTML'
    });
    return true;
  } catch (error) {
    console.error('Telegram error:', error);
    return false;
  }
};

// Admin Login Route (للأدمن فقط باستخدام username)
app.post('/api/auth/admin-login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    // التحقق من username و password من .env
    if (username !== process.env.ADMIN_USERNAME || password !== process.env.ADMIN_PASSWORD) {
      return res.status(401).json({ error: 'Invalid admin credentials' });
    }

    // البحث عن المستخدم في Firebase
    const usersSnapshot = await db.collection('users')
      .where('email', '==', process.env.ADMIN_EMAIL)
      .get();

    let userData;
    let userId;

    if (usersSnapshot.empty) {
      // لو الأدمن مش موجود في Firebase، نضيفه
      const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
      const newAdmin = {
        fullName: 'Admin',
        email: process.env.ADMIN_EMAIL,
        password: hashedPassword,
        role: 'admin',
        accountName: 'Admin',
        username: process.env.ADMIN_USERNAME,
        createdAt: new Date().toISOString(),
        isActive: true
      };
      const docRef = await db.collection('users').add(newAdmin);
      userId = docRef.id;
      userData = newAdmin;
    } else {
      const doc = usersSnapshot.docs[0];
      userId = doc.id;
      userData = doc.data();
    }

    // Create JWT
    const token = jwt.sign(
      { 
        userId: userId, 
        email: userData.email, 
        role: 'admin',
        fullName: userData.fullName 
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE || '24h' }
    );

    res.json({ 
      token, 
      user: {
        id: userId,
        fullName: userData.fullName,
        email: userData.email,
        role: 'admin',
        accountName: userData.accountName || userData.fullName
      }
    });

  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Auth Routes
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { fullName, email, password, confirmPassword } = req.body;

    // Validation
    if (!fullName || !email || !password || !confirmPassword) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user exists
    const usersSnapshot = await db.collection('users')
      .where('email', '==', email)
      .get();

    if (!usersSnapshot.empty) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const userData = {
      fullName,
      email,
      password: hashedPassword,
      role: 'user',
      accountName: fullName,
      createdAt: new Date().toISOString(),
      isActive: true
    };

    const docRef = await db.collection('users').add(userData);

    // Send welcome email
    await sendEmail(
      email,
      'Welcome to Dr. Mirna Safwat Pharmacy',
      `<h1>Welcome ${fullName}</h1>
       <p>Thank you for registering with Dr. Mirna Safwat Pharmacy.</p>
       <p>Your account has been created successfully.</p>`
    );

    // Send Telegram notification
    await sendTelegram(`🆕 New User Registration\n\nName: ${fullName}\nEmail: ${email}\nRole: User`);

    // Log audit
    await db.collection('auditLogs').add({
      adminName: 'System',
      action: 'User Registration',
      date: new Date().toISOString(),
      ip: req.ip,
      recordId: docRef.id
    });

    res.status(201).json({ 
      message: 'User created successfully',
      userId: docRef.id 
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Find user by email
    const usersSnapshot = await db.collection('users')
      .where('email', '==', email)
      .get();

    if (usersSnapshot.empty) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const userDoc = usersSnapshot.docs[0];
    const userData = userDoc.data();

    // Check if user is active
    if (!userData.isActive) {
      return res.status(401).json({ error: 'Account is deactivated' });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, userData.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Create JWT
    const token = jwt.sign(
      { 
        userId: userDoc.id, 
        email: userData.email, 
        role: userData.role,
        fullName: userData.fullName 
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE || '24h' }
    );

    res.json({ 
      token, 
      user: {
        id: userDoc.id,
        fullName: userData.fullName,
        email: userData.email,
        role: userData.role,
        accountName: userData.accountName || userData.fullName
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    // Find user
    const usersSnapshot = await db.collection('users')
      .where('email', '==', email)
      .get();

    if (usersSnapshot.empty) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userDoc = usersSnapshot.docs[0];
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 2 * 60 * 1000); // 2 minutes

    // Save OTP
    await db.collection('resetTokens').add({
      userId: userDoc.id,
      email: email,
      otp: otp,
      expiresAt: expiresAt.toISOString(),
      used: false
    });

    // Send OTP email
    await sendEmail(
      email,
      'Password Reset OTP - Dr. Mirna Safwat Pharmacy',
      `<h1>Password Reset</h1>
       <p>Your OTP for password reset is: <strong>${otp}</strong></p>
       <p>This OTP is valid for 2 minutes.</p>
       <p>If you didn't request this, please ignore this email.</p>`
    );

    res.json({ message: 'OTP sent to your email' });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword, confirmPassword } = req.body;

    if (!email || !otp || !newPassword || !confirmPassword) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Verify OTP
    const tokensSnapshot = await db.collection('resetTokens')
      .where('email', '==', email)
      .where('otp', '==', otp)
      .where('used', '==', false)
      .get();

    if (tokensSnapshot.empty) {
      return res.status(400).json({ error: 'Invalid OTP' });
    }

    const tokenDoc = tokensSnapshot.docs[0];
    const tokenData = tokenDoc.data();

    // Check expiry
    if (new Date(tokenData.expiresAt) < new Date()) {
      return res.status(400).json({ error: 'OTP expired' });
    }

    // Find user
    const usersSnapshot = await db.collection('users')
      .where('email', '==', email)
      .get();

    if (usersSnapshot.empty) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userDoc = usersSnapshot.docs[0];

    // Update password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await userDoc.ref.update({
      password: hashedPassword,
      updatedAt: new Date().toISOString()
    });

    // Mark OTP as used
    await tokenDoc.ref.update({ used: true });

    // Log audit
    await db.collection('auditLogs').add({
      adminName: userDoc.data().fullName,
      action: 'Password Reset',
      date: new Date().toISOString(),
      ip: req.ip,
      recordId: userDoc.id
    });

    res.json({ message: 'Password reset successful' });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Protected Routes
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const userDoc = await db.collection('users').doc(req.user.userId).get();
    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userData = userDoc.data();
    res.json({
      id: userDoc.id,
      fullName: userData.fullName,
      email: userData.email,
      role: userData.role,
      accountName: userData.accountName || userData.fullName
    });

  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Medicine Routes
app.post('/api/medicines', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { name, category, price, stock, description, image } = req.body;

    if (!name || !price || !stock) {
      return res.status(400).json({ error: 'Name, price, and stock are required' });
    }

    // Upload image to Cloudinary if provided
    let imageUrl = null;
    if (image) {
      const uploadResult = await cloudinary.uploader.upload(image, {
        folder: 'pharmacy/medicines'
      });
      imageUrl = uploadResult.secure_url;
    }

    const medicineData = {
      name,
      category: category || 'General',
      price: parseFloat(price),
      stock: parseInt(stock),
      description: description || '',
      imageUrl,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    const docRef = await db.collection('medicines').add(medicineData);

    // Log audit
    await db.collection('auditLogs').add({
      adminName: req.user.fullName,
      action: 'Medicine Added',
      date: new Date().toISOString(),
      ip: req.ip,
      recordId: docRef.id
    });

    res.status(201).json({ 
      message: 'Medicine added successfully',
      id: docRef.id,
      ...medicineData
    });

  } catch (error) {
    console.error('Add medicine error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/medicines', authenticateToken, async (req, res) => {
  try {
    const snapshot = await db.collection('medicines')
      .orderBy('createdAt', 'desc')
      .get();

    const medicines = [];
    snapshot.forEach(doc => {
      medicines.push({ id: doc.id, ...doc.data() });
    });

    res.json(medicines);

  } catch (error) {
    console.error('Get medicines error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/medicines/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, category, price, stock, description, image } = req.body;

    const medicineRef = db.collection('medicines').doc(id);
    const doc = await medicineRef.get();

    if (!doc.exists) {
      return res.status(404).json({ error: 'Medicine not found' });
    }

    let updateData = {
      name: name || doc.data().name,
      category: category || doc.data().category,
      price: price ? parseFloat(price) : doc.data().price,
      stock: stock ? parseInt(stock) : doc.data().stock,
      description: description || doc.data().description,
      updatedAt: new Date().toISOString()
    };

    // Upload new image if provided
    if (image) {
      const uploadResult = await cloudinary.uploader.upload(image, {
        folder: 'pharmacy/medicines'
      });
      updateData.imageUrl = uploadResult.secure_url;
    }

    await medicineRef.update(updateData);

    // Log audit
    await db.collection('auditLogs').add({
      adminName: req.user.fullName,
      action: 'Medicine Updated',
      date: new Date().toISOString(),
      ip: req.ip,
      recordId: id
    });

    res.json({ message: 'Medicine updated successfully' });

  } catch (error) {
    console.error('Update medicine error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/medicines/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const medicineRef = db.collection('medicines').doc(id);
    const doc = await medicineRef.get();

    if (!doc.exists) {
      return res.status(404).json({ error: 'Medicine not found' });
    }

    await medicineRef.delete();

    // Log audit
    await db.collection('auditLogs').add({
      adminName: req.user.fullName,
      action: 'Medicine Deleted',
      date: new Date().toISOString(),
      ip: req.ip,
      recordId: id
    });

    res.json({ message: 'Medicine deleted successfully' });

  } catch (error) {
    console.error('Delete medicine error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Orders Routes
app.post('/api/orders', authenticateToken, async (req, res) => {
  try {
    const { 
      orderType, 
      items, 
      totalAmount, 
      paymentMethod, 
      transactionId,
      customerName,
      customerEmail,
      customerPhone,
      deliveryAddress,
      specialInstructions
    } = req.body;

    const orderData = {
      userId: req.user.userId,
      userEmail: req.user.email,
      userAccountName: req.user.fullName,
      orderType: orderType || 'medicine',
      items: items || [],
      totalAmount: parseFloat(totalAmount) || 0,
      paymentMethod: paymentMethod || 'pending',
      transactionId: transactionId || '',
      status: 'pending',
      customerName: customerName || req.user.fullName,
      customerEmail: customerEmail || req.user.email,
      customerPhone: customerPhone || '',
      deliveryAddress: deliveryAddress || '',
      specialInstructions: specialInstructions || '',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    const docRef = await db.collection('orders').add(orderData);

    // AI Payment Verification (تلقائي في الخلفية)
    const isMatch = transactionId === process.env.PAYMENT_REFERENCE_NUMBER;
    const aiResult = {
      status: isMatch ? 'AI Passed' : 'AI Failed',
      message: isMatch ? 'Payment verified automatically' : 'Payment verification failed'
    };

    // Update order with AI verification result
    await docRef.update({
      aiVerification: aiResult,
      aiVerifiedAt: new Date().toISOString()
    });

    // Send Telegram notification
    await sendTelegram(
      `🛒 New Order Created\n\n` +
      `Order ID: ${docRef.id}\n` +
      `Type: ${orderType}\n` +
      `Customer: ${req.user.fullName}\n` +
      `Total: $${orderData.totalAmount}\n` +
      `AI Status: ${aiResult.status}\n` +
      `Status: Pending`
    );

    res.status(201).json({ 
      message: 'Order created successfully',
      orderId: docRef.id,
      aiVerification: aiResult,
      ...orderData
    });

  } catch (error) {
    console.error('Create order error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    let query = db.collection('orders').orderBy('createdAt', 'desc');
    
    // If not admin, show only user's orders
    if (req.user.role !== 'admin') {
      query = query.where('userId', '==', req.user.userId);
    }

    const snapshot = await query.get();
    const orders = [];
    snapshot.forEach(doc => {
      orders.push({ id: doc.id, ...doc.data() });
    });

    res.json(orders);

  } catch (error) {
    console.error('Get orders error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/orders/:id/status', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, rejectionReason } = req.body;

    if (!['pending', 'approved', 'rejected'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const orderRef = db.collection('orders').doc(id);
    const doc = await orderRef.get();

    if (!doc.exists) {
      return res.status(404).json({ error: 'Order not found' });
    }

    const orderData = doc.data();
    const updateData = {
      status: status,
      updatedAt: new Date().toISOString()
    };

    if (status === 'rejected') {
      updateData.rejectionReason = rejectionReason || 'No reason provided';
    }

    await orderRef.update(updateData);

    // If approved, add to sales
    if (status === 'approved') {
      await db.collection('sales').add({
        orderId: id,
        productName: orderData.orderType || 'Order',
        productType: orderData.orderType || 'general',
        quantity: orderData.items?.length || 1,
        unitPrice: orderData.totalAmount / (orderData.items?.length || 1),
        totalPrice: orderData.totalAmount,
        customerAccountName: orderData.userAccountName || orderData.customerName,
        notes: `Approved order ${id}`,
        saleDate: new Date().toISOString(),
        userId: orderData.userId,
        userEmail: orderData.userEmail,
        createdAt: new Date().toISOString()
      });

      // Update analytics
      const analyticsRef = db.collection('analytics').doc('summary');
      const analyticsDoc = await analyticsRef.get();
      if (analyticsDoc.exists) {
        const data = analyticsDoc.data();
        await analyticsRef.update({
          totalSales: (data.totalSales || 0) + 1,
          totalRevenue: (data.totalRevenue || 0) + orderData.totalAmount,
          approvedOrders: (data.approvedOrders || 0) + 1
        });
      } else {
        await analyticsRef.set({
          totalSales: 1,
          totalRevenue: orderData.totalAmount,
          totalOrders: 1,
          pendingOrders: 0,
          approvedOrders: 1,
          rejectedOrders: 0,
          medicineSales: 0,
          offerSales: 0,
          packageSales: 0,
          updatedAt: new Date().toISOString()
        });
      }
    }

    // Send notifications
    const userEmail = orderData.userEmail || orderData.customerEmail;
    const userName = orderData.userAccountName || orderData.customerName;

    if (status === 'approved') {
      await sendEmail(
        userEmail,
        'Order Approved - Dr. Mirna Safwat Pharmacy',
        `<h1>Order Approved ✅</h1>
         <p>Dear ${userName},</p>
         <p>Your order #${id} has been approved.</p>
         <p>Total Amount: $${orderData.totalAmount}</p>
         <p>Thank you for shopping with us!</p>`
      );

      await sendTelegram(
        `✅ Order Approved\n\n` +
        `Order ID: ${id}\n` +
        `Customer: ${userName}\n` +
        `Amount: $${orderData.totalAmount}\n` +
        `Approved by: ${req.user.fullName}`
      );
    } else if (status === 'rejected') {
      await sendEmail(
        userEmail,
        'Order Rejected - Dr. Mirna Safwat Pharmacy',
        `<h1>Order Rejected ❌</h1>
         <p>Dear ${userName},</p>
         <p>Your order #${id} has been rejected.</p>
         <p>Reason: ${updateData.rejectionReason}</p>
         <p>Please contact us if you have any questions.</p>`
      );

      await sendTelegram(
        `❌ Order Rejected\n\n` +
        `Order ID: ${id}\n` +
        `Customer: ${userName}\n` +
        `Reason: ${updateData.rejectionReason}\n` +
        `Rejected by: ${req.user.fullName}`
      );
    }

    // Log audit
    await db.collection('auditLogs').add({
      adminName: req.user.fullName,
      action: `Order ${status}`,
      date: new Date().toISOString(),
      ip: req.ip,
      recordId: id
    });

    res.json({ message: `Order ${status} successfully` });

  } catch (error) {
    console.error('Update order status error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Analytics Routes
app.get('/api/analytics', authenticateToken, isAdmin, async (req, res) => {
  try {
    const analyticsRef = db.collection('analytics').doc('summary');
    const doc = await analyticsRef.get();

    if (!doc.exists) {
      return res.json({
        totalSales: 0,
        totalRevenue: 0,
        totalOrders: 0,
        pendingOrders: 0,
        approvedOrders: 0,
        rejectedOrders: 0,
        medicineSales: 0,
        offerSales: 0,
        packageSales: 0
      });
    }

    res.json(doc.data());

  } catch (error) {
    console.error('Get analytics error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// AI Routes
app.post('/api/ai/chat', authenticateToken, async (req, res) => {
  try {
    const { message } = req.body;

    // Search for medicine in Firestore
    const medicinesSnapshot = await db.collection('medicines')
      .where('name', '>=', message)
      .where('name', '<=', message + '\uf8ff')
      .limit(1)
      .get();

    if (!medicinesSnapshot.empty) {
      const medicine = medicinesSnapshot.docs[0].data();
      res.json({
        response: `✅ ${medicine.name} is available.\nPrice: $${medicine.price}\nStock: ${medicine.stock} units\nCategory: ${medicine.category}`
      });
    } else {
      res.json({
        response: `❌ Medicine "${message}" not found.\nPlease contact the pharmacy: ${process.env.PHARMACY_PHONE}`
      });
    }

  } catch (error) {
    console.error('AI chat error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// SMTP Sender Route
app.post('/api/smtp/send', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { to, subject, message } = req.body;

    if (!to || !subject || !message) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    await sendEmail(
      to,
      subject,
      `<p>${message.replace(/\n/g, '<br>')}</p>
       <br>
       <p>---</p>
       <p>Sent from Dr. Mirna Safwat Pharmacy Dashboard</p>`
    );

    // Log audit
    await db.collection('auditLogs').add({
      adminName: req.user.fullName,
      action: 'SMTP Email Sent',
      date: new Date().toISOString(),
      ip: req.ip,
      recordId: `email-${Date.now()}`
    });

    res.json({ message: 'Email sent successfully' });

  } catch (error) {
    console.error('SMTP send error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Expenses Routes
app.post('/api/expenses', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { name, amount, notes } = req.body;

    if (!name || !amount) {
      return res.status(400).json({ error: 'Name and amount are required' });
    }

    const expenseData = {
      name,
      amount: parseFloat(amount),
      notes: notes || '',
      date: new Date().toISOString(),
      createdAt: new Date().toISOString()
    };

    const docRef = await db.collection('expenses').add(expenseData);

    res.status(201).json({
      message: 'Expense added successfully',
      id: docRef.id,
      ...expenseData
    });

  } catch (error) {
    console.error('Add expense error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/expenses', authenticateToken, isAdmin, async (req, res) => {
  try {
    const snapshot = await db.collection('expenses')
      .orderBy('date', 'desc')
      .get();

    const expenses = [];
    snapshot.forEach(doc => {
      expenses.push({ id: doc.id, ...doc.data() });
    });

    res.json(expenses);

  } catch (error) {
    console.error('Get expenses error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Audit Logs Routes
app.get('/api/audit-logs', authenticateToken, isAdmin, async (req, res) => {
  try {
    const snapshot = await db.collection('auditLogs')
      .orderBy('date', 'desc')
      .limit(100)
      .get();

    const logs = [];
    snapshot.forEach(doc => {
      logs.push({ id: doc.id, ...doc.data() });
    });

    res.json(logs);

  } catch (error) {
    console.error('Get audit logs error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Telegram Notification Route
app.post('/api/telegram/notify', authenticateToken, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }
    await sendTelegram(message);
    res.json({ success: true });
  } catch (error) {
    console.error('Telegram notify error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Serve HTML files
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login-dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login-dashboard.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
});

app.get('/pay', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'pay.html'));
});

app.get('/offer', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'offer.html'));
});

app.get('/package', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'package.html'));
});

app.get('/pay-offer', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'pay-offer.html'));
});

app.get('/pay-package', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'pay-package.html'));
});

app.get('/privacy-policy', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'privacy-policy.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
