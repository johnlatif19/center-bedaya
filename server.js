require('dotenv').config();
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

// Telegram Notification Function - Only for bookings and contacts
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

    // No Telegram notification for signup

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

    // No Telegram notification for login

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

    // No Telegram notification for admin login

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
], authenticateToken, async (req, res) => {
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

    // Send Telegram notification for bookings only
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
], authenticateToken, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, phone, message } = req.body;

    // Save contact to database
    const contactData = {
      name,
      email,
      phone,
      message,
      createdAt: new Date().toISOString()
    };

    await db.collection('contacts').add(contactData);

    // Send email with beautiful HTML template
    const mailOptions = {
      from: process.env.SMTP_USER,
      to: process.env.ADMIN_EMAIL,
      subject: '📩 رسالة جديدة من مركز بداية',
      html: `
        <!DOCTYPE html>
        <html dir="rtl" lang="ar">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>رسالة جديدة</title>
          <style>
            body {
              font-family: 'Cairo', 'Tahoma', sans-serif;
              background-color: #f8fafc;
              margin: 0;
              padding: 0;
              direction: rtl;
            }
            .container {
              max-width: 600px;
              margin: 0 auto;
              background-color: #ffffff;
              border-radius: 16px;
              overflow: hidden;
              box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
              margin-top: 30px;
              margin-bottom: 30px;
            }
            .header {
              background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
              padding: 30px 40px;
              text-align: center;
            }
            .header h1 {
              color: #ffffff;
              font-size: 28px;
              font-weight: 800;
              margin: 0;
              letter-spacing: 1px;
            }
            .header .subtitle {
              color: rgba(255, 255, 255, 0.8);
              font-size: 16px;
              margin-top: 8px;
            }
            .header .logo {
              font-size: 48px;
              margin-bottom: 10px;
              display: block;
            }
            .content {
              padding: 40px 40px 30px;
            }
            .content .greeting {
              font-size: 20px;
              font-weight: 700;
              color: #1e293b;
              margin-bottom: 20px;
            }
            .content .message-label {
              font-weight: 700;
              color: #1e293b;
              font-size: 16px;
              margin-bottom: 10px;
              display: block;
            }
            .content .message-box {
              background-color: #f1f5f9;
              padding: 20px;
              border-radius: 12px;
              border-right: 4px solid #4f46e5;
              color: #334155;
              line-height: 1.8;
              margin-bottom: 25px;
            }
            .info-grid {
              display: grid;
              grid-template-columns: 100px 1fr;
              gap: 8px 16px;
              background-color: #f8fafc;
              padding: 16px 20px;
              border-radius: 12px;
              margin-bottom: 25px;
            }
            .info-grid .label {
              font-weight: 700;
              color: #475569;
              font-size: 14px;
            }
            .info-grid .value {
              color: #1e293b;
              font-size: 14px;
            }
            .footer {
              background-color: #f1f5f9;
              padding: 20px 40px;
              text-align: center;
              border-top: 1px solid #e2e8f0;
            }
            .footer p {
              color: #94a3b8;
              font-size: 13px;
              margin: 0;
            }
            .footer .brand {
              color: #4f46e5;
              font-weight: 700;
            }
            .badge {
              display: inline-block;
              background: linear-gradient(135deg, #4f46e5, #7c3aed);
              color: #fff;
              padding: 4px 16px;
              border-radius: 20px;
              font-size: 12px;
              font-weight: 700;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <span class="logo">🏥</span>
              <h1>مركز بداية</h1>
              <p class="subtitle">للتدخل المبكر والتأهيل</p>
              <span class="badge" style="margin-top: 12px;">📩 رسالة جديدة</span>
            </div>
            <div class="content">
              <p class="greeting">📬 لديك رسالة جديدة من أحد الزوار</p>
              
              <div class="info-grid">
                <span class="label">👤 الاسم:</span>
                <span class="value">${name}</span>
                <span class="label">📧 البريد:</span>
                <span class="value">${email}</span>
                <span class="label">📱 الهاتف:</span>
                <span class="value">${phone}</span>
              </div>
              
              <span class="message-label">📝 محتوى الرسالة:</span>
              <div class="message-box">
                ${message}
              </div>
            </div>
            <div class="footer">
              <p>© ${new Date().getFullYear()} <span class="brand">مركز بداية</span> - جميع الحقوق محفوظة</p>
              <p style="font-size: 11px; color: #cbd5e1; margin-top: 4px;">هذه رسالة آلية من نظام التواصل</p>
            </div>
          </div>
        </body>
        </html>
      `
    };

    await transporter.sendMail(mailOptions);

    // Send Telegram notification for contacts only
    await sendTelegramNotification(
      `📧 <b>رسالة تواصل جديدة</b>\n\n` +
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

    // No Telegram notification for sales

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

// Update Sale
app.put('/api/admin/sales/:id', authenticateAdmin, [
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

    await db.collection('sales').doc(req.params.id).update({
      customer,
      amount: parseFloat(amount),
      date: today,
      updatedAt: new Date().toISOString()
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Update sale error:', error);
    res.status(500).json({ error: 'Error updating sale' });
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

// ==================== CONTACTS ROUTES ====================

// Get Contacts
app.get('/api/admin/contacts', authenticateAdmin, async (req, res) => {
  try {
    const contactsSnapshot = await db.collection('contacts')
      .orderBy('createdAt', 'desc')
      .get();

    const contacts = [];
    contactsSnapshot.forEach(doc => {
      contacts.push({ id: doc.id, ...doc.data() });
    });

    res.json(contacts);
  } catch (error) {
    console.error('Get contacts error:', error);
    res.status(500).json({ error: 'Error fetching contacts' });
  }
});

// Delete Contact
app.delete('/api/admin/contacts/:id', authenticateAdmin, async (req, res) => {
  try {
    await db.collection('contacts').doc(req.params.id).delete();
    res.json({ success: true });
  } catch (error) {
    console.error('Delete contact error:', error);
    res.status(500).json({ error: 'Error deleting contact' });
  }
});

// ==================== RESULTS ADMIN ROUTES ====================

// Get Results
app.get('/api/admin/results', authenticateAdmin, async (req, res) => {
  try {
    const resultsSnapshot = await db.collection('results')
      .orderBy('createdAt', 'desc')
      .get();

    const results = [];
    resultsSnapshot.forEach(doc => {
      results.push({ id: doc.id, ...doc.data() });
    });

    res.json(results);
  } catch (error) {
    console.error('Get results error:', error);
    res.status(500).json({ error: 'Error fetching results' });
  }
});

// Update Result
app.put('/api/admin/results/:id', authenticateAdmin, [
  body('phone').notEmpty().withMessage('رقم التليفون مطلوب'),
  body('url').notEmpty().withMessage('رابط الملف مطلوب')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { phone, url } = req.body;

    await db.collection('results').doc(req.params.id).update({
      phone,
      url,
      updatedAt: new Date().toISOString()
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Update result error:', error);
    res.status(500).json({ error: 'Error updating result' });
  }
});

// Delete Result
app.delete('/api/admin/results/:id', authenticateAdmin, async (req, res) => {
  try {
    await db.collection('results').doc(req.params.id).delete();
    res.json({ success: true });
  } catch (error) {
    console.error('Delete result error:', error);
    res.status(500).json({ error: 'Error deleting result' });
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

    // No Telegram notification for results

    res.json({
      success: true,
      message: 'تم حفظ النتيجة بنجاح'
    });
  } catch (error) {
    console.error('Upload result error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء حفظ النتيجة' });
  }
});

// Upload Result (by File)
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

    // No Telegram notification for results

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

// ==================== MESSAGES ROUTES ====================

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

// Send Email with beautiful template
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
      subject: '📩 رسالة من مركز بداية للتدخل المبكر والتأهيل',
      html: `
        <!DOCTYPE html>
        <html dir="rtl" lang="ar">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>رسالة من مركز بداية</title>
          <style>
            body {
              font-family: 'Cairo', 'Tahoma', sans-serif;
              background-color: #f8fafc;
              margin: 0;
              padding: 0;
              direction: rtl;
            }
            .container {
              max-width: 600px;
              margin: 0 auto;
              background-color: #ffffff;
              border-radius: 16px;
              overflow: hidden;
              box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
              margin-top: 30px;
              margin-bottom: 30px;
            }
            .header {
              background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
              padding: 30px 40px;
              text-align: center;
            }
            .header h1 {
              color: #ffffff;
              font-size: 28px;
              font-weight: 800;
              margin: 0;
              letter-spacing: 1px;
            }
            .header .subtitle {
              color: rgba(255, 255, 255, 0.8);
              font-size: 16px;
              margin-top: 8px;
            }
            .header .logo {
              font-size: 48px;
              margin-bottom: 10px;
              display: block;
            }
            .content {
              padding: 40px 40px 30px;
            }
            .content .greeting {
              font-size: 20px;
              font-weight: 700;
              color: #1e293b;
              margin-bottom: 10px;
            }
            .content .message-box {
              background-color: #f1f5f9;
              padding: 24px;
              border-radius: 12px;
              border-right: 4px solid #4f46e5;
              color: #334155;
              line-height: 1.8;
              font-size: 16px;
              margin-bottom: 20px;
            }
            .content .footer-text {
              color: #64748b;
              font-size: 14px;
              line-height: 1.6;
            }
            .footer {
              background-color: #f1f5f9;
              padding: 20px 40px;
              text-align: center;
              border-top: 1px solid #e2e8f0;
            }
            .footer p {
              color: #94a3b8;
              font-size: 13px;
              margin: 0;
            }
            .footer .brand {
              color: #4f46e5;
              font-weight: 700;
            }
            .divider {
              height: 1px;
              background: linear-gradient(to right, transparent, #4f46e5, transparent);
              margin: 20px 0;
            }
            .badge {
              display: inline-block;
              background: linear-gradient(135deg, #4f46e5, #7c3aed);
              color: #fff;
              padding: 4px 16px;
              border-radius: 20px;
              font-size: 12px;
              font-weight: 700;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <span class="logo">🏥</span>
              <h1>مركز بداية</h1>
              <p class="subtitle">للتدخل المبكر والتأهيل</p>
              <span class="badge" style="margin-top: 12px;">📨 رسالة رسمية</span>
            </div>
            <div class="content">
              <p class="greeting">🌹 مرحباً بك،</p>
              <div class="message-box">
                ${message.replace(/\n/g, '<br>')}
              </div>
              <div class="divider"></div>
              <p class="footer-text">
                💙 مع تحيات <strong style="color: #4f46e5;">مركز بداية</strong> للتدخل المبكر والتأهيل<br>
                📍 ٢٩ شارع سلطان ابو العلا، العروبة، امبابة<br>
                📱 للتواصل: 01278127159
              </p>
            </div>
            <div class="footer">
              <p>© ${new Date().getFullYear()} <span class="brand">مركز بداية</span> - جميع الحقوق محفوظة</p>
              <p style="font-size: 11px; color: #cbd5e1; margin-top: 4px;">هذه رسالة آلية، يرجى عدم الرد على هذا البريد</p>
            </div>
          </div>
        </body>
        </html>
      `
    };

    await transporter.sendMail(mailOptions);

    // Save to database
    await db.collection('messages').add({
      email,
      message,
      sentAt: new Date().toISOString()
    });

    // No Telegram notification for emails

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

// ==================== SERVE HTML PAGES ====================

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
