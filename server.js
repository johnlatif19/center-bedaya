('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const path = require('path');
const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const nodemailer = require('nodemailer');
const cloudinary = require('cloudinary').v2;
const axios = require('axios');
const multer = require('multer');

// Initialize Firebase
const firebaseConfig = JSON.parse(process.env.FIREBASE_CONFIG);
admin.initializeApp({
  credential: admin.credential.cert(firebaseConfig)
});
const db = admin.firestore();

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Configure Nodemailer
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// Initialize Express
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());
app.use(express.static('public'));

// Configure Multer for file uploads
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token.' });
  }
};

const authenticateAdmin = (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.isAdmin) {
      return res.status(403).json({ error: 'Admin access required.' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token.' });
  }
};

// Telegram Notification Function
const sendTelegramNotification = async (message) => {
  try {
    const url = `https://api.telegram.org/bot${process.env.TELEGRAM_TOKEN}/sendMessage`;
    await axios.post(url, {
      chat_id: process.env.TELEGRAM_CHAT_ID,
      text: message,
      parse_mode: 'HTML'
    });
  } catch (error) {
    console.error('Telegram notification error:', error);
  }
};

// Helper Functions
const generateToken = (user, isAdmin = false) => {
  return jwt.sign(
    { 
      id: user.id, 
      email: user.email, 
      username: user.fullName || user.username,
      isAdmin 
    },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
};

// ==================== AUTH ROUTES ====================

// Signup
app.post('/api/auth/signup', [
  body('fullName').notEmpty().withMessage('الاسم مطلوب'),
  body('email').isEmail().withMessage('بريد إلكتروني غير صحيح'),
  body('password').isLength({ min: 6 }).withMessage('كلمة المرور يجب أن تكون 6 أحرف على الأقل'),
  body('confirmPassword').custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error('كلمات المرور غير متطابقة');
    }
    return true;
  })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { fullName, email, password } = req.body;

    // Check if user exists
    const userSnapshot = await db.collection('users')
      .where('email', '==', email)
      .get();

    if (!userSnapshot.empty) {
      return res.status(400).json({ error: 'البريد الإلكتروني مستخدم بالفعل' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const userData = {
      fullName,
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };

    const docRef = await db.collection('users').add(userData);
    const user = { id: docRef.id, ...userData };

    // Generate token
    const token = generateToken(user);

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    // Send Telegram notification
    await sendTelegramNotification(
      `🆕 <b>تسجيل جديد</b>\n\n` +
      `👤 الاسم: ${fullName}\n` +
      `📧 البريد: ${email}`
    );

    res.status(201).json({
      success: true,
      user: { id: user.id, fullName, email }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء التسجيل' });
  }
});

// Login
app.post('/api/auth/login', [
  body('email').notEmpty().withMessage('البريد الإلكتروني مطلوب'),
  body('password').notEmpty().withMessage('كلمة المرور مطلوبة')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    // Find user
    const userSnapshot = await db.collection('users')
      .where('email', '==', email)
      .get();

    if (userSnapshot.empty) {
      return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
    }

    const doc = userSnapshot.docs[0];
    const user = { id: doc.id, ...doc.data() };

    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
    }

    // Generate token
    const token = generateToken(user);

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    // Send Telegram notification
    await sendTelegramNotification(
      `🔐 <b>تسجيل دخول</b>\n\n` +
      `👤 المستخدم: ${user.fullName}\n` +
      `📧 البريد: ${user.email}`
    );

    res.json({
      success: true,
      user: { id: user.id, fullName: user.fullName, email: user.email }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء تسجيل الدخول' });
  }
});

// Admin Login
app.post('/api/auth/admin-login', [
  body('username').notEmpty().withMessage('اسم المستخدم مطلوب'),
  body('password').notEmpty().withMessage('كلمة المرور مطلوبة')
], async (req, res) => {
  try {
    const { username, password } = req.body;

    // Check admin credentials
    if (username !== process.env.ADMIN_USERNAME || 
        password !== process.env.ADMIN_PASSWORD) {
      return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
    }

    // Check if admin exists in database
    let adminSnapshot = await db.collection('users')
      .where('email', '==', process.env.ADMIN_EMAIL)
      .get();

    let adminUser;
    if (adminSnapshot.empty) {
      // Create admin user
      const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
      const adminData = {
        fullName: 'Admin',
        email: process.env.ADMIN_EMAIL,
        password: hashedPassword,
        isAdmin: true,
        createdAt: new Date().toISOString()
      };
      const docRef = await db.collection('users').add(adminData);
      adminUser = { id: docRef.id, ...adminData };
    } else {
      const doc = adminSnapshot.docs[0];
      adminUser = { id: doc.id, ...doc.data() };
    }

    // Generate token
    const token = generateToken(adminUser, true);

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    await sendTelegramNotification(
      `👑 <b>تسجيل دخول إداري</b>\n\n` +
      `👤 المدير: ${process.env.ADMIN_USERNAME}`
    );

    res.json({
      success: true,
      admin: { 
        id: adminUser.id, 
        email: adminUser.email, 
        username: process.env.ADMIN_USERNAME 
      }
    });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء تسجيل الدخول' });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

// Verify Token
app.get('/api/auth/verify', authenticateToken, async (req, res) => {
  try {
    const doc = await db.collection('users').doc(req.user.id).get();
    if (!doc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }
    const userData = doc.data();
    res.json({
      authenticated: true,
      user: {
        id: doc.id,
        fullName: userData.fullName,
        email: userData.email,
        isAdmin: userData.isAdmin || false
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Error verifying token' });
  }
});

// ==================== BOOKING ROUTES ====================

app.post('/api/bookings', [
  body('fullName').notEmpty().withMessage('الاسم الكامل مطلوب'),
  body('phone').notEmpty().withMessage('رقم التليفون مطلوب'),
  body('date').notEmpty().withMessage('التاريخ مطلوب'),
  body('time').notEmpty().withMessage('الوقت مطلوب')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { fullName, phone, date, time } = req.body;

    const booking = {
      fullName,
      phone,
      date,
      time,
      createdAt: new Date().toISOString()
    };

    const docRef = await db.collection('bookings').add(booking);

    await sendTelegramNotification(
      `📅 <b>حجز جديد</b>\n\n` +
      `👤 الاسم: ${fullName}\n` +
      `📱 التليفون: ${phone}\n` +
      `📆 التاريخ: ${date}\n` +
      `🕐 الوقت: ${time}`
    );

    res.status(201).json({
      success: true,
      booking: { id: docRef.id, ...booking }
    });
  } catch (error) {
    console.error('Booking error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء الحجز' });
  }
});

// ==================== CONTACT ROUTES ====================

app.post('/api/contact', [
  body('name').notEmpty().withMessage('الاسم مطلوب'),
  body('email').isEmail().withMessage('بريد إلكتروني غير صحيح'),
  body('phone').notEmpty().withMessage('رقم التليفون مطلوب'),
  body('message').notEmpty().withMessage('الرسالة مطلوبة')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, phone, message } = req.body;

    // Send email
    const mailOptions = {
      from: process.env.SMTP_USER,
      to: process.env.ADMIN_EMAIL,
      subject: 'رسالة جديدة من مركز بداية',
      html: `
        <h2>رسالة جديدة من موقع مركز بداية</h2>
        <p><strong>الاسم:</strong> ${name}</p>
        <p><strong>البريد الإلكتروني:</strong> ${email}</p>
        <p><strong>رقم التليفون:</strong> ${phone}</p>
        <p><strong>الرسالة:</strong></p>
        <p>${message}</p>
      `
    };

    await transporter.sendMail(mailOptions);

    await sendTelegramNotification(
      `📧 <b>رسالة جديدة</b>\n\n` +
      `👤 الاسم: ${name}\n` +
      `📧 البريد: ${email}\n` +
      `📱 التليفون: ${phone}\n` +
      `💬 الرسالة: ${message}`
    );

    res.json({
      success: true,
      message: 'تم إرسال الرسالة بنجاح'
    });
  } catch (error) {
    console.error('Contact error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء إرسال الرسالة' });
  }
});

// ==================== RESULTS ROUTES ====================

app.post('/api/results/check', [
  body('phone').notEmpty().withMessage('رقم التليفون مطلوب')
], async (req, res) => {
  try {
    const { phone } = req.body;

    const resultsSnapshot = await db.collection('results')
      .where('phone', '==', phone)
      .get();

    if (resultsSnapshot.empty) {
      return res.json({ exists: false });
    }

    const doc = resultsSnapshot.docs[0];
    const result = { id: doc.id, ...doc.data() };

    res.json({
      exists: true,
      result: {
        phone: result.phone,
        url: result.url,
        createdAt: result.createdAt
      }
    });
  } catch (error) {
    console.error('Result check error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء البحث' });
  }
});

// ==================== ADMIN DASHBOARD ROUTES ====================

// Get Dashboard Stats
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    
    // Get today's sales
    const salesSnapshot = await db.collection('sales')
      .where('date', '==', today)
      .get();
    
    let todaySales = 0;
    salesSnapshot.forEach(doc => {
      todaySales += doc.data().amount;
    });

    // Get total bookings
    const bookingsSnapshot = await db.collection('bookings').get();
    const totalBookings = bookingsSnapshot.size;

    // Get total messages
    const messagesSnapshot = await db.collection('messages').get();
    const totalMessages = messagesSnapshot.size;

    res.json({
      todaySales,
      totalBookings,
      totalMessages
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Error fetching stats' });
  }
});

// Get Sales Chart Data
app.get('/api/admin/sales-chart', authenticateAdmin, async (req, res) => {
  try {
    const salesSnapshot = await db.collection('sales')
      .orderBy('date', 'desc')
      .limit(30)
      .get();

    const salesData = [];
    salesSnapshot.forEach(doc => {
      const data = doc.data();
      salesData.push({
        date: data.date,
        amount: data.amount,
        customer: data.customer
      });
    });

    res.json(salesData.reverse());
  } catch (error) {
    console.error('Sales chart error:', error);
    res.status(500).json({ error: 'Error fetching sales data' });
  }
});

// Add Sale
app.post('/api/admin/sales', authenticateAdmin, [
  body('customer').notEmpty().withMessage('اسم العميل مطلوب'),
  body('amount').isNumeric().withMessage('المبلغ يجب أن يكون رقماً')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { customer, amount } = req.body;
    const today = new Date().toISOString().split('T')[0];

    const sale = {
      customer,
      amount: parseFloat(amount),
      date: today,
      createdAt: new Date().toISOString()
    };

    const docRef = await db.collection('sales').add(sale);

    await sendTelegramNotification(
      `💰 <b>عملية بيع جديدة</b>\n\n` +
      `👤 العميل: ${customer}\n` +
      `💵 المبلغ: ${amount} جنيه`
    );

    res.status(201).json({
      success: true,
      sale: { id: docRef.id, ...sale }
    });
  } catch (error) {
    console.error('Add sale error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء تسجيل البيع' });
  }
});

// Get Sales
app.get('/api/admin/sales', authenticateAdmin, async (req, res) => {
  try {
    const salesSnapshot = await db.collection('sales')
      .orderBy('createdAt', 'desc')
      .get();

    const sales = [];
    salesSnapshot.forEach(doc => {
      sales.push({ id: doc.id, ...doc.data() });
    });

    res.json(sales);
  } catch (error) {
    console.error('Get sales error:', error);
    res.status(500).json({ error: 'Error fetching sales' });
  }
});

// Delete Sale
app.delete('/api/admin/sales/:id', authenticateAdmin, async (req, res) => {
  try {
    await db.collection('sales').doc(req.params.id).delete();
    res.json({ success: true });
  } catch (error) {
    console.error('Delete sale error:', error);
    res.status(500).json({ error: 'Error deleting sale' });
  }
});

// Get Bookings
app.get('/api/admin/bookings', authenticateAdmin, async (req, res) => {
  try {
    const bookingsSnapshot = await db.collection('bookings')
      .orderBy('createdAt', 'desc')
      .get();

    const bookings = [];
    bookingsSnapshot.forEach(doc => {
      bookings.push({ id: doc.id, ...doc.data() });
    });

    res.json(bookings);
  } catch (error) {
    console.error('Get bookings error:', error);
    res.status(500).json({ error: 'Error fetching bookings' });
  }
});

// Delete Booking
app.delete('/api/admin/bookings/:id', authenticateAdmin, async (req, res) => {
  try {
    await db.collection('bookings').doc(req.params.id).delete();
    res.json({ success: true });
  } catch (error) {
    console.error('Delete booking error:', error);
    res.status(500).json({ error: 'Error deleting booking' });
  }
});

// Upload Result (by URL - legacy)
app.post('/api/admin/results', authenticateAdmin, [
  body('phone').notEmpty().withMessage('رقم التليفون مطلوب'),
  body('url').notEmpty().withMessage('رابط الملف مطلوب')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { phone, url } = req.body;

    // Check if result exists
    const existingSnapshot = await db.collection('results')
      .where('phone', '==', phone)
      .get();

    if (!existingSnapshot.empty) {
      // Update existing
      const doc = existingSnapshot.docs[0];
      await db.collection('results').doc(doc.id).update({
        url,
        updatedAt: new Date().toISOString()
      });
    } else {
      // Create new
      await db.collection('results').add({
        phone,
        url,
        createdAt: new Date().toISOString()
      });
    }

    await sendTelegramNotification(
      `📄 <b>نتيجة جديدة</b>\n\n` +
      `📱 رقم التليفون: ${phone}\n` +
      `🔗 رابط النتيجة: ${url}`
    );

    res.json({
      success: true,
      message: 'تم حفظ النتيجة بنجاح'
    });
  } catch (error) {
    console.error('Upload result error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء حفظ النتيجة' });
  }
});

// Upload Result (by File - new)
app.post('/api/admin/results/upload', authenticateAdmin, upload.single('file'), async (req, res) => {
  try {
    const { phone } = req.body;
    const file = req.file;

    if (!file) {
      return res.status(400).json({ error: 'الملف مطلوب' });
    }

    if (!phone) {
      return res.status(400).json({ error: 'رقم الهاتف مطلوب' });
    }

    // Upload to Cloudinary
    const result = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream({
        folder: 'results',
        resource_type: 'auto'
      }, (error, result) => {
        if (error) reject(error);
        else resolve(result);
      });
      uploadStream.end(file.buffer);
    });

    const url = result.secure_url;

    // Save to Firestore
    const existingSnapshot = await db.collection('results')
      .where('phone', '==', phone)
      .get();

    if (!existingSnapshot.empty) {
      const doc = existingSnapshot.docs[0];
      await db.collection('results').doc(doc.id).update({
        url,
        updatedAt: new Date().toISOString()
      });
    } else {
      await db.collection('results').add({
        phone,
        url,
        createdAt: new Date().toISOString()
      });
    }

    await sendTelegramNotification(
      `📄 <b>نتيجة جديدة</b>\n\n` +
      `📱 رقم التليفون: ${phone}\n` +
      `🔗 رابط النتيجة: ${url}`
    );

    res.json({ 
      success: true, 
      url,
      message: 'تم رفع النتيجة بنجاح'
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء رفع الملف' });
  }
});

// Get Messages
app.get('/api/admin/messages', authenticateAdmin, async (req, res) => {
  try {
    const messagesSnapshot = await db.collection('messages')
      .orderBy('sentAt', 'desc')
      .get();

    const messages = [];
    messagesSnapshot.forEach(doc => {
      messages.push({ id: doc.id, ...doc.data() });
    });

    res.json(messages);
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ error: 'Error fetching messages' });
  }
});

// Send Email
app.post('/api/admin/send-email', authenticateAdmin, [
  body('email').isEmail().withMessage('بريد إلكتروني غير صحيح'),
  body('message').notEmpty().withMessage('الرسالة مطلوبة')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, message } = req.body;

    const mailOptions = {
      from: process.env.SMTP_USER,
      to: email,
      subject: 'رسالة من مركز بداية للتدخل المبكر والتأهيل',
      html: `
        <div style="font-family: Arial, sans-serif; direction: rtl; text-align: right;">
          <h2 style="color: #4F46E5;">مركز بداية للتدخل المبكر والتأهيل</h2>
          <p>${message}</p>
          <hr>
          <p style="color: #666; font-size: 12px;">هذه رسالة آلية، يرجى عدم الرد على هذا البريد.</p>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);

    // Save to database
    await db.collection('messages').add({
      email,
      message,
      sentAt: new Date().toISOString()
    });

    await sendTelegramNotification(
      `📧 <b>رسالة مرسلة</b>\n\n` +
      `📧 إلى: ${email}\n` +
      `💬 الرسالة: ${message.substring(0, 100)}...`
    );

    res.json({
      success: true,
      message: 'تم إرسال الرسالة بنجاح'
    });
  } catch (error) {
    console.error('Send email error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء إرسال الرسالة' });
  }
});

// Delete Message
app.delete('/api/admin/messages/:id', authenticateAdmin, async (req, res) => {
  try {
    await db.collection('messages').doc(req.params.id).delete();
    res.json({ success: true });
  } catch (error) {
    console.error('Delete message error:', error);
    res.status(500).json({ error: 'Error deleting message' });
  }
});

// Serve HTML pages
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/login-dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login-dashboard.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`🌐 http://localhost:${PORT}`);
});
