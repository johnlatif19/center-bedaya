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

// Telegram Notification Function - Only for Bookings and Contact
const sendTelegramNotification = async (message, type) => {
  // Only send for bookings and contact messages
  if (type !== 'booking' && type !== 'contact') {
    console.log('Telegram notification skipped for type:', type);
    return;
  }
  
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
      sameSide: 'strict',
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

    // Send Telegram notification for booking only
    await sendTelegramNotification(
      `📅 <b>حجز جديد</b>\n\n` +
      `👤 الاسم: ${fullName}\n` +
      `📱 التليفون: ${phone}\n` +
      `📆 التاريخ: ${date}\n` +
      `🕐 الوقت: ${time}`,
      'booking'
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

    // Save contact message to database
    const contactData = {
      name,
      email,
      phone,
      message,
      sentAt: new Date().toISOString()
    };
    await db.collection('contacts').add(contactData);

    // Send email with improved HTML design
    const mailOptions = {
      from: process.env.SMTP_USER,
      to: process.env.ADMIN_EMAIL,
      subject: 'رسالة جديدة من مركز بداية',
      html: `
        <!DOCTYPE html>
        <html dir="rtl" lang="ar">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>رسالة جديدة</title>
        </head>
        <body style="font-family: 'Cairo', Arial, sans-serif; direction: rtl; text-align: right; background-color: #0f172a; margin: 0; padding: 0;">
          <div style="max-width: 600px; margin: 20px auto; background: linear-gradient(135deg, #1e1b4b, #312e81); border-radius: 16px; overflow: hidden; box-shadow: 0 20px 60px rgba(0,0,0,0.5); border: 1px solid rgba(79,70,229,0.2);">
            <!-- Header with Logo -->
            <div style="padding: 30px 30px 20px; text-align: center; border-bottom: 1px solid rgba(79,70,229,0.2);">
              <div style="display: inline-block; background: linear-gradient(135deg, #4f46e5, #7c3aed); padding: 15px 25px; border-radius: 12px; margin-bottom: 10px;">
                <span style="font-size: 28px; font-weight: 800; color: #ffffff;">BEDAYA</span>
                <span style="font-size: 20px; font-weight: 400; color: #a78bfa; margin-right: 8px;">مركز بداية</span>
              </div>
              <div style="margin-top: 8px;">
                <span style="font-size: 13px; color: #94a3b8;">للتدخل المبكر والتأهيل</span>
              </div>
            </div>
            
            <!-- Content -->
            <div style="padding: 30px; background: rgba(15, 23, 42, 0.6);">
              <div style="background: rgba(79, 70, 229, 0.08); border-right: 4px solid #4f46e5; padding: 15px 20px; border-radius: 8px; margin-bottom: 25px;">
                <h2 style="color: #e2e8f0; font-size: 20px; margin: 0; font-weight: 700;">📩 رسالة جديدة من موقع مركز بداية</h2>
              </div>
              
              <div style="background: rgba(30, 41, 59, 0.5); border-radius: 12px; padding: 20px; border: 1px solid rgba(79,70,229,0.1);">
                <div style="display: flex; padding: 10px 0; border-bottom: 1px solid rgba(79,70,229,0.08);">
                  <span style="color: #94a3b8; min-width: 120px; font-weight: 600;">👤 الاسم:</span>
                  <span style="color: #e2e8f0;">${name}</span>
                </div>
                <div style="display: flex; padding: 10px 0; border-bottom: 1px solid rgba(79,70,229,0.08);">
                  <span style="color: #94a3b8; min-width: 120px; font-weight: 600;">📧 البريد الإلكتروني:</span>
                  <span style="color: #e2e8f0;">${email}</span>
                </div>
                <div style="display: flex; padding: 10px 0; border-bottom: 1px solid rgba(79,70,229,0.08);">
                  <span style="color: #94a3b8; min-width: 120px; font-weight: 600;">📱 رقم التليفون:</span>
                  <span style="color: #e2e8f0;">${phone}</span>
                </div>
                <div style="display: flex; padding: 12px 0 0;">
                  <span style="color: #94a3b8; min-width: 120px; font-weight: 600;">💬 الرسالة:</span>
                  <span style="color: #e2e8f0; flex: 1; line-height: 1.8; background: rgba(15,23,42,0.5); padding: 12px; border-radius: 8px; margin-top: 4px;">${message}</span>
                </div>
              </div>
            </div>
            
            <!-- Footer -->
            <div style="padding: 20px 30px; text-align: center; border-top: 1px solid rgba(79,70,229,0.1); background: rgba(15, 23, 42, 0.4);">
              <p style="color: #64748b; font-size: 12px; margin: 0;">
                © 2025 مركز بداية للتدخل المبكر والتأهيل | جميع الحقوق محفوظة
              </p>
              <p style="color: #475569; font-size: 10px; margin: 5px 0 0;">
                هذه رسالة آلية، يرجى عدم الرد على هذا البريد.
              </p>
            </div>
          </div>
        </body>
        </html>
      `
    };

    await transporter.sendMail(mailOptions);

    // Send Telegram notification for contact only
    await sendTelegramNotification(
      `📧 <b>رسالة جديدة</b>\n\n` +
      `👤 الاسم: ${name}\n` +
      `📧 البريد: ${email}\n` +
      `📱 التليفون: ${phone}\n` +
      `💬 الرسالة: ${message}`,
      'contact'
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
], authenticateToken, async (req, res) => {
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
        id: result.id,
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
    
    // Get total contacts
    const contactsSnapshot = await db.collection('contacts').get();
    const totalContacts = contactsSnapshot.size;

    res.json({
      todaySales,
      totalBookings,
      totalMessages,
      totalContacts
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
    const saleRef = db.collection('sales').doc(req.params.id);
    const saleDoc = await saleRef.get();

    if (!saleDoc.exists) {
      return res.status(404).json({ error: 'Sale not found' });
    }

    await saleRef.update({
      customer,
      amount: parseFloat(amount),
      updatedAt: new Date().toISOString()
    });

    res.json({
      success: true,
      message: 'تم تحديث البيع بنجاح'
    });
  } catch (error) {
    console.error('Update sale error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث البيع' });
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

    let resultId;
    if (!existingSnapshot.empty) {
      const doc = existingSnapshot.docs[0];
      resultId = doc.id;
      await db.collection('results').doc(doc.id).update({
        url,
        updatedAt: new Date().toISOString()
      });
    } else {
      const newDoc = await db.collection('results').add({
        phone,
        url,
        createdAt: new Date().toISOString()
      });
      resultId = newDoc.id;
    }

    // No Telegram notification for results

    res.json({ 
      success: true, 
      url,
      id: resultId,
      message: 'تم رفع النتيجة بنجاح'
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء رفع الملف' });
  }
});

// Update Result with file upload
app.put('/api/admin/results/:id', authenticateAdmin, upload.single('file'), async (req, res) => {
  try {
    const { phone } = req.body;
    const file = req.file;
    const resultId = req.params.id;

    if (!phone) {
      return res.status(400).json({ error: 'رقم الهاتف مطلوب' });
    }

    const resultRef = db.collection('results').doc(resultId);
    const resultDoc = await resultRef.get();

    if (!resultDoc.exists) {
      return res.status(404).json({ error: 'Result not found' });
    }

    let updateData = {
      phone,
      updatedAt: new Date().toISOString()
    };

    // If a file was uploaded, upload to Cloudinary
    if (file) {
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
      updateData.url = result.secure_url;
    }

    await resultRef.update(updateData);

    res.json({
      success: true,
      message: 'تم تحديث النتيجة بنجاح'
    });
  } catch (error) {
    console.error('Update result error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث النتيجة' });
  }
});

// Get all results (for admin)
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

// Get Contacts
app.get('/api/admin/contacts', authenticateAdmin, async (req, res) => {
  try {
    const contactsSnapshot = await db.collection('contacts')
      .orderBy('sentAt', 'desc')
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
        <!DOCTYPE html>
        <html dir="rtl" lang="ar">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>رسالة من مركز بداية</title>
        </head>
        <body style="font-family: 'Cairo', Arial, sans-serif; direction: rtl; text-align: right; background-color: #0f172a; margin: 0; padding: 0;">
          <div style="max-width: 600px; margin: 20px auto; background: linear-gradient(135deg, #1e1b4b, #312e81); border-radius: 16px; overflow: hidden; box-shadow: 0 20px 60px rgba(0,0,0,0.5); border: 1px solid rgba(79,70,229,0.2);">
            <!-- Header with Logo -->
            <div style="padding: 30px 30px 20px; text-align: center; border-bottom: 1px solid rgba(79,70,229,0.2);">
              <div style="display: inline-block; background: linear-gradient(135deg, #4f46e5, #7c3aed); padding: 15px 25px; border-radius: 12px; margin-bottom: 10px;">
                <span style="font-size: 28px; font-weight: 800; color: #ffffff;">BEDAYA</span>
                <span style="font-size: 20px; font-weight: 400; color: #a78bfa; margin-right: 8px;">مركز بداية</span>
              </div>
              <div style="margin-top: 8px;">
                <span style="font-size: 13px; color: #94a3b8;">للتدخل المبكر والتأهيل</span>
              </div>
            </div>
            
            <!-- Content -->
            <div style="padding: 30px; background: rgba(15, 23, 42, 0.6);">
              <div style="background: rgba(79, 70, 229, 0.08); border-right: 4px solid #4f46e5; padding: 15px 20px; border-radius: 8px; margin-bottom: 25px;">
                <h2 style="color: #e2e8f0; font-size: 20px; margin: 0; font-weight: 700;">📧 رسالة من مركز بداية</h2>
              </div>
              
              <div style="background: rgba(30, 41, 59, 0.5); border-radius: 12px; padding: 20px; border: 1px solid rgba(79,70,229,0.1);">
                <div style="color: #e2e8f0; line-height: 2; font-size: 16px; white-space: pre-wrap;">
                  ${message}
                </div>
              </div>
            </div>
            
            <!-- Footer -->
            <div style="padding: 20px 30px; text-align: center; border-top: 1px solid rgba(79,70,229,0.1); background: rgba(15, 23, 42, 0.4);">
              <p style="color: #64748b; font-size: 12px; margin: 0;">
                © 2025 مركز بداية للتدخل المبكر والتأهيل | جميع الحقوق محفوظة
              </p>
              <p style="color: #475569; font-size: 10px; margin: 5px 0 0;">
                هذه رسالة آلية، يرجى عدم الرد على هذا البريد.
              </p>
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

    // No Telegram notification for email

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

// Verify Admin - مخصص للداشبورد
app.get('/api/auth/verify-admin', authenticateToken, async (req, res) => {
  try {
    // تحقق من أن المستخدم مدير
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const doc = await db.collection('users').doc(req.user.id).get();
    if (!doc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const userData = doc.data();
    if (!userData.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    res.json({
      authenticated: true,
      admin: {
        id: doc.id,
        email: userData.email,
        username: userData.fullName || 'Admin'
      }
    });
  } catch (error) {
    console.error('Verify admin error:', error);
    res.status(500).json({ error: 'Error verifying admin' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`🌐 http://localhost:${PORT}`);
});
