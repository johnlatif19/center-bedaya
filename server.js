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

// ============================================
// TOKEN BLACKLIST SYSTEM
// ============================================
const blacklistedTokens = db.collection('blacklisted_tokens');

const blacklistToken = async (token) => {
  if (!token) return;
  try {
    const decoded = jwt.decode(token);
    const expiresIn = decoded?.exp ? (decoded.exp * 1000 - Date.now()) : 7 * 24 * 60 * 60 * 1000;
    await blacklistedTokens.doc(token).set({
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + expiresIn).toISOString()
    });
  } catch (error) {
    console.error('Error blacklisting token:', error);
  }
};

const isTokenBlacklisted = async (token) => {
  if (!token) return false;
  try {
    const doc = await blacklistedTokens.doc(token).get();
    return doc.exists;
  } catch (error) {
    console.error('Error checking blacklist:', error);
    return false;
  }
};

// Clean up expired tokens every hour
setInterval(async () => {
  try {
    const now = new Date().toISOString();
    const expiredTokens = await blacklistedTokens
      .where('expiresAt', '<=', now)
      .get();
    
    const batch = db.batch();
    expiredTokens.forEach(doc => {
      batch.delete(doc.ref);
    });
    await batch.commit();
    if (expiredTokens.size > 0) {
      console.log(`🧹 Cleaned up ${expiredTokens.size} expired tokens from blacklist`);
    }
  } catch (error) {
    console.error('Error cleaning up blacklisted tokens:', error);
  }
}, 60 * 60 * 1000);

// ============================================
// CONCURRENCY THROTTLING
// ============================================
let activeRequests = 0;
const MAX_CONCURRENT_REQUESTS = 20;

// ============================================
// MIDDLEWARE
// ============================================
app.use(helmet());
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());
app.use(express.static('public'));

// Concurrency throttling middleware
app.use((req, res, next) => {
  if (req.path.match(/\.(css|js|png|jpg|jpeg|gif|svg|ico|webp|woff|woff2|ttf)$/)) {
    return next();
  }

  if (activeRequests >= MAX_CONCURRENT_REQUESTS) {
    return res.status(503).json({
      error: 'الخادم مشغول حالياً، يرجى المحاولة بعد قليل',
      retryAfter: 5
    });
  }

  activeRequests++;

  res.on('finish', () => {
    activeRequests--;
  });
  res.on('close', () => {
    activeRequests--;
  });

  next();
});

// Request timeout
app.use((req, res, next) => {
  req.setTimeout(30000, () => {
    res.status(504).json({ error: 'انتهت مهلة الطلب، يرجى المحاولة مرة أخرى' });
  });
  next();
});

// Configure Multer for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }
});

// ============================================
// RATE LIMITING
// ============================================
const blockedIPs = new Map();

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  handler: (req, res) => {
    const ip = req.ip;
    const now = Date.now();
    const blockDuration = 30 * 1000;
    const unlockTime = now + blockDuration;
    blockedIPs.set(ip, unlockTime);

    const remainingSeconds = Math.ceil(blockDuration / 1000);
    
    res.status(429).json({
      error: `تم تجاوز عدد الطلبات المسموح بها، يرجى الانتظار ${remainingSeconds} ثانية`,
      retryAfter: remainingSeconds,
      remainingSeconds: remainingSeconds
    });
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path.match(/\.(css|js|png|jpg|jpeg|gif|svg|ico|webp|woff|woff2|ttf)$/),
  keyGenerator: (req) => req.ip
});

// IP block check middleware
app.use((req, res, next) => {
  if (req.path.match(/\.(css|js|png|jpg|jpeg|gif|svg|ico|webp|woff|woff2|ttf)$/)) {
    return next();
  }
  
  const ip = req.ip;
  if (blockedIPs.has(ip)) {
    const unlockTime = blockedIPs.get(ip);
    const now = Date.now();
    if (now < unlockTime) {
      const remainingSeconds = Math.ceil((unlockTime - now) / 1000);
      return res.status(429).json({
        error: `تم تجاوز عدد الطلبات المسموح بها، يرجى الانتظار ${remainingSeconds} ثانية`,
        retryAfter: remainingSeconds,
        remainingSeconds: remainingSeconds
      });
    } else {
      blockedIPs.delete(ip);
    }
  }
  next();
});

app.use('/api/', limiter);

// Clean up blocked IPs every minute
setInterval(() => {
  const now = Date.now();
  for (const [ip, unlockTime] of blockedIPs) {
    if (now >= unlockTime) {
      blockedIPs.delete(ip);
    }
  }
}, 60000);

// ============================================
// JWT AUTHENTICATION MIDDLEWARE
// ============================================
const authenticateToken = async (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }
  
  try {
    if (await isTokenBlacklisted(token)) {
      res.clearCookie('token');
      return res.status(401).json({ 
        error: 'Session expired. Please login again.',
        code: 'TOKEN_BLACKLISTED'
      });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      await blacklistedTokens.doc(token).delete().catch(() => {});
    }
    return res.status(403).json({ error: 'Invalid token.' });
  }
};

const authenticateAdmin = async (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }
  
  try {
    if (await isTokenBlacklisted(token)) {
      res.clearCookie('token');
      return res.status(401).json({ 
        error: 'Session expired. Please login again.',
        code: 'TOKEN_BLACKLISTED'
      });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.isAdmin) {
      return res.status(403).json({ error: 'Admin access required.' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      await blacklistedTokens.doc(token).delete().catch(() => {});
    }
    return res.status(403).json({ error: 'Invalid token.' });
  }
};

// ============================================
// HELPER FUNCTIONS
// ============================================
const generateToken = (user, isAdmin = false, adminData = null) => {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      username: user.fullName || user.username,
      isAdmin,
      adminUsername: adminData?.adminUsername || null
    },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
};

const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

const otpStore = {};

const sendTelegramNotification = async (message, type) => {
  if (type !== 'booking' && type !== 'contact') return;
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

const sendEmail = async (to, subject, html) => {
  try {
    await transporter.sendMail({
      from: process.env.SMTP_USER,
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

// ============================================
// AUTH ROUTES
// ============================================

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

    const { fullName, email, password, phone } = req.body;

    const userSnapshot = await db.collection('users')
      .where('email', '==', email)
      .get();

    if (!userSnapshot.empty) {
      return res.status(400).json({ error: 'البريد الإلكتروني مستخدم بالفعل' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userData = {
      fullName,
      email,
      phone: phone || '',
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };

    const docRef = await db.collection('users').add(userData);
    const user = { id: docRef.id, ...userData };
    const token = generateToken(user);

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    // Send welcome email (async, don't wait for result)
    const welcomeHtml = `
      <!DOCTYPE html>
      <html dir="rtl" lang="ar">
      <head><meta charset="UTF-8"><title>مرحباً بك في مركز بداية</title></head>
      <body style="font-family: 'Cairo', Arial, sans-serif; direction: rtl; text-align: right; background-color: #0f172a; margin: 0; padding: 0;">
        <div style="max-width: 600px; margin: 20px auto; background: linear-gradient(135deg, #1e1b4b, #312e81); border-radius: 16px; overflow: hidden; box-shadow: 0 20px 60px rgba(0,0,0,0.5); border: 1px solid rgba(79,70,229,0.2);">
          <div style="padding: 30px 30px 20px; text-align: center; border-bottom: 1px solid rgba(79,70,229,0.2);">
            <div style="display: inline-block; background: linear-gradient(135deg, #4f46e5, #7c3aed); padding: 15px 25px; border-radius: 12px; margin-bottom: 10px;">
              <span style="font-size: 28px; font-weight: 800; color: #ffffff;">bedaya</span>
              <span style="font-size: 20px; font-weight: 400; color: #a78bfa; margin-right: 8px;">مركز بداية</span>
            </div>
            <div style="margin-top: 8px;"><span style="font-size: 13px; color: #94a3b8;">للتدخل المبكر والتأهيل</span></div>
          </div>
          <div style="padding: 30px; background: rgba(15, 23, 42, 0.6);">
            <div style="background: rgba(79, 70, 229, 0.08); border-right: 4px solid #4f46e5; padding: 15px 20px; border-radius: 8px; margin-bottom: 25px;">
              <h2 style="color: #e2e8f0; font-size: 20px; margin: 0; font-weight: 700;">🎉 مرحباً ${fullName}!</h2>
            </div>
            <div style="background: rgba(30, 41, 59, 0.5); border-radius: 12px; padding: 20px; border: 1px solid rgba(79,70,229,0.1);">
              <p style="color: #e2e8f0; font-size: 16px; line-height: 1.8; margin-bottom: 20px;">
                نشكرك على التسجيل في <strong style="color: #818cf8;">مركز بداية للتدخل المبكر والتأهيل</strong>.
              </p>
              <p style="color: #e2e8f0; font-size: 16px; line-height: 1.8; margin-bottom: 20px;">
                نحن سعداء بانضمامك إلينا! يمكنك الآن:
              </p>
              <ul style="color: #94a3b8; font-size: 15px; line-height: 2; padding-right: 20px;">
                <li>📅 حجز موعد في المركز</li>
                <li>📊 الاستعلام عن نتائجك</li>
                <li>📧 التواصل مع الفريق</li>
              </ul>
              <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid rgba(79,70,229,0.1);">
                <div style="display: flex; padding: 8px 0;">
                  <span style="color: #94a3b8; min-width: 100px; font-weight: 600;">👤 الاسم:</span>
                  <span style="color: #e2e8f0;">${fullName}</span>
                </div>
                <div style="display: flex; padding: 8px 0;">
                  <span style="color: #94a3b8; min-width: 100px; font-weight: 600;">📧 البريد الإلكتروني:</span>
                  <span style="color: #e2e8f0;">${email}</span>
                </div>
                ${phone ? `<div style="display: flex; padding: 8px 0;">
                  <span style="color: #94a3b8; min-width: 100px; font-weight: 600;">📱 رقم الهاتف:</span>
                  <span style="color: #e2e8f0;">${phone}</span>
                </div>` : ''}
              </div>
            </div>
          </div>
          <div style="padding: 20px 30px; text-align: center; border-top: 1px solid rgba(79,70,229,0.1); background: rgba(15, 23, 42, 0.4);">
            <p style="color: #64748b; font-size: 12px; margin: 0;">© 2025 مركز بداية للتدخل المبكر والتأهيل | جميع الحقوق محفوظة</p>
          </div>
        </div>
      </body>
      </html>
    `;
    sendEmail(email, 'مرحباً بك في مركز بداية للتدخل المبكر والتأهيل', welcomeHtml).catch(console.error);

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

    const userSnapshot = await db.collection('users')
      .where('email', '==', email)
      .get();

    if (userSnapshot.empty) {
      return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
    }

    const doc = userSnapshot.docs[0];
    const user = { id: doc.id, ...doc.data() };

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
    }

    const token = generateToken(user);

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      success: true,
      user: { id: user.id, fullName: user.fullName, email: user.email, phone: user.phone || '' }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء تسجيل الدخول' });
  }
});

// Admin Login - MODIFIED (no adminName)
app.post('/api/auth/admin-login', [
  body('username').notEmpty().withMessage('اسم المستخدم مطلوب'),
  body('password').notEmpty().withMessage('كلمة المرور مطلوبة')
], async (req, res) => {
  try {
    const { username, password } = req.body;

    if (username !== process.env.ADMIN_USERNAME || password !== process.env.ADMIN_PASSWORD) {
      return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
    }

    const adminUsername = process.env.ADMIN_USERNAME;

    let adminSnapshot = await db.collection('users')
      .where('email', '==', process.env.ADMIN_EMAIL)
      .get();

    let adminUser;

    if (adminSnapshot.empty) {
      const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
      const adminData = {
        fullName: adminUsername,
        email: process.env.ADMIN_EMAIL,
        password: hashedPassword,
        isAdmin: true,
        adminUsername: adminUsername,
        createdAt: new Date().toISOString()
      };
      const docRef = await db.collection('users').add(adminData);
      adminUser = { id: docRef.id, ...adminData };
    } else {
      const doc = adminSnapshot.docs[0];
      const docData = doc.data();
      
      if (docData.adminUsername !== adminUsername) {
        await db.collection('users').doc(doc.id).update({
          adminUsername: adminUsername,
          fullName: adminUsername,
          updatedAt: new Date().toISOString()
        });
        docData.adminUsername = adminUsername;
        docData.fullName = adminUsername;
      }
      
      adminUser = { id: doc.id, ...docData };
    }

    const token = generateToken(adminUser, true, { adminUsername });

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      success: true,
      admin: {
        id: adminUser.id,
        email: adminUser.email,
        username: adminUsername
      }
    });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء تسجيل الدخول' });
  }
});

// Logout
app.post('/api/auth/logout', async (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  if (token) {
    await blacklistToken(token);
  }
  res.clearCookie('token');
  res.json({ success: true });
});

// Logout All
app.post('/api/auth/logout-all', async (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  
  if (token) {
    try {
      await blacklistToken(token);
      const decoded = jwt.decode(token);
      if (decoded && decoded.id) {
        console.log(`User ${decoded.id} logged out from all devices`);
      }
    } catch (error) {
      console.error('Error in logout-all:', error);
    }
  }
  
  res.clearCookie('token');
  res.json({ success: true });
});

// Revoke user tokens (admin only)
app.post('/api/admin/revoke-user-tokens', authenticateAdmin, async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) {
      return res.status(400).json({ error: 'User ID is required' });
    }
    
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    if (token) {
      await blacklistToken(token);
    }
    
    res.json({ 
      success: true, 
      message: 'تم إبطال جميع توكنات المستخدم بنجاح' 
    });
  } catch (error) {
    console.error('Revoke tokens error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء إبطال التوكنات' });
  }
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
        phone: userData.phone || '',
        isAdmin: userData.isAdmin || false
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Error verifying token' });
  }
});

// Verify Admin
app.get('/api/auth/verify-admin', authenticateToken, async (req, res) => {
  try {
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
        username: userData.adminUsername || userData.fullName || 'Admin'
      }
    });
  } catch (error) {
    console.error('Verify admin error:', error);
    res.status(500).json({ error: 'Error verifying admin' });
  }
});

// Forgot Password
app.post('/api/auth/forgot-password', [
  body('email').isEmail().withMessage('بريد إلكتروني غير صحيح')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email } = req.body;

    const userSnapshot = await db.collection('users')
      .where('email', '==', email)
      .get();

    if (userSnapshot.empty) {
      return res.status(404).json({ error: 'لا يوجد حساب بهذا البريد الإلكتروني' });
    }

    const doc = userSnapshot.docs[0];
    const user = { id: doc.id, ...doc.data() };

    const otp = generateOTP();
    const expiresAt = Date.now() + 5 * 60 * 1000;

    otpStore[email] = {
      otp,
      expiresAt,
      userId: user.id
    };

    const resetLink = `${req.protocol}://${req.get('host')}/reset-password`;

    const mailHtml = `
      <!DOCTYPE html>
      <html dir="rtl" lang="ar">
      <head><meta charset="UTF-8"><title>إعادة تعيين كلمة المرور</title></head>
      <body style="font-family: 'Cairo', Arial, sans-serif; direction: rtl; text-align: right; background-color: #0f172a; margin: 0; padding: 0;">
        <div style="max-width: 600px; margin: 20px auto; background: linear-gradient(135deg, #1e1b4b, #312e81); border-radius: 16px; overflow: hidden; box-shadow: 0 20px 60px rgba(0,0,0,0.5); border: 1px solid rgba(79,70,229,0.2);">
          <div style="padding: 30px 30px 20px; text-align: center; border-bottom: 1px solid rgba(79,70,229,0.2);">
            <div style="display: inline-block; background: linear-gradient(135deg, #4f46e5, #7c3aed); padding: 15px 25px; border-radius: 12px; margin-bottom: 10px;">
              <span style="font-size: 28px; font-weight: 800; color: #ffffff;">BEDAYA</span>
              <span style="font-size: 20px; font-weight: 400; color: #a78bfa; margin-right: 8px;">مركز بداية</span>
            </div>
            <div style="margin-top: 8px;"><span style="font-size: 13px; color: #94a3b8;">للتدخل المبكر والتأهيل</span></div>
          </div>
          <div style="padding: 30px; background: rgba(15, 23, 42, 0.6);">
            <div style="background: rgba(79, 70, 229, 0.08); border-right: 4px solid #4f46e5; padding: 15px 20px; border-radius: 8px; margin-bottom: 25px;">
              <h2 style="color: #e2e8f0; font-size: 20px; margin: 0; font-weight: 700;">🔐 إعادة تعيين كلمة المرور</h2>
            </div>
            <div style="background: rgba(30, 41, 59, 0.5); border-radius: 12px; padding: 20px; border: 1px solid rgba(79,70,229,0.1);">
              <p style="color: #e2e8f0; font-size: 16px; line-height: 1.8;">
                لقد تلقينا طلباً لإعادة تعيين كلمة المرور لحسابك في <strong style="color: #818cf8;">مركز بداية</strong>.
              </p>
              <div style="background: rgba(79,70,229,0.15); border-radius: 12px; padding: 20px; text-align: center; margin: 20px 0;">
                <p style="color: #94a3b8; font-size: 14px; margin-bottom: 8px;">رمز التحقق (OTP):</p>
                <div style="font-size: 36px; font-weight: 800; color: #818cf8; letter-spacing: 8px; background: rgba(15,23,42,0.5); padding: 10px 20px; border-radius: 8px; display: inline-block;">
                  ${otp}
                </div>
                <p style="color: #ef4444; font-size: 12px; margin-top: 8px;">⚠️ هذا الرمز صالح لمدة 5 دقائق فقط</p>
              </div>
              <div style="text-align: center; margin-top: 20px;">
                <a href="${resetLink}" style="display: inline-block; padding: 12px 30px; background: linear-gradient(135deg, #4f46e5, #7c3aed); color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: 700; font-size: 16px;">
                  الذهاب إلى صفحة إعادة التعيين
                </a>
              </div>
            </div>
          </div>
          <div style="padding: 20px 30px; text-align: center; border-top: 1px solid rgba(79,70,229,0.1); background: rgba(15, 23, 42, 0.4);">
            <p style="color: #64748b; font-size: 12px; margin: 0;">© 2025 مركز بداية للتدخل المبكر والتأهيل | جميع الحقوق محفوظة</p>
          </div>
        </div>
      </body>
      </html>
    `;

    await sendEmail(email, 'إعادة تعيين كلمة المرور - مركز بداية', mailHtml);

    res.json({
      success: true,
      message: 'تم إرسال رمز التحقق إلى بريدك الإلكتروني'
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء إرسال رمز التحقق' });
  }
});

// Verify OTP
app.post('/api/auth/verify-otp', [
  body('email').isEmail().withMessage('بريد إلكتروني غير صحيح'),
  body('otp').notEmpty().withMessage('رمز التحقق مطلوب')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, otp } = req.body;

    const storedOTP = otpStore[email];
    if (!storedOTP) {
      return res.status(400).json({ error: 'رمز التحقق غير صحيح أو منتهي الصلاحية' });
    }

    if (storedOTP.otp !== otp) {
      return res.status(400).json({ error: 'رمز التحقق غير صحيح' });
    }

    if (Date.now() > storedOTP.expiresAt) {
      delete otpStore[email];
      return res.status(400).json({ error: 'انتهت صلاحية رمز التحقق (5 دقائق)' });
    }

    res.json({
      success: true,
      message: 'تم التحقق من الرمز بنجاح'
    });
  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء التحقق' });
  }
});

// Reset Password
app.post('/api/auth/reset-password', [
  body('email').isEmail().withMessage('بريد إلكتروني غير صحيح'),
  body('otp').notEmpty().withMessage('رمز التحقق مطلوب'),
  body('password').isLength({ min: 6 }).withMessage('كلمة المرور يجب أن تكون 6 أحرف على الأقل')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, otp, password } = req.body;

    const storedOTP = otpStore[email];
    if (!storedOTP) {
      return res.status(400).json({ error: 'رمز التحقق غير صحيح أو منتهي الصلاحية' });
    }

    if (storedOTP.otp !== otp) {
      return res.status(400).json({ error: 'رمز التحقق غير صحيح' });
    }

    if (Date.now() > storedOTP.expiresAt) {
      delete otpStore[email];
      return res.status(400).json({ error: 'انتهت صلاحية رمز التحقق (5 دقائق)' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.collection('users').doc(storedOTP.userId).update({
      password: hashedPassword,
      updatedAt: new Date().toISOString()
    });

    delete otpStore[email];

    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    if (token) {
      await blacklistToken(token);
    }

    const confirmHtml = `
      <!DOCTYPE html>
      <html dir="rtl" lang="ar">
      <head><meta charset="UTF-8"><title>تم تغيير كلمة المرور</title></head>
      <body style="font-family: 'Cairo', Arial, sans-serif; direction: rtl; text-align: right; background-color: #0f172a; margin: 0; padding: 0;">
        <div style="max-width: 600px; margin: 20px auto; background: linear-gradient(135deg, #1e1b4b, #312e81); border-radius: 16px; overflow: hidden; box-shadow: 0 20px 60px rgba(0,0,0,0.5); border: 1px solid rgba(79,70,229,0.2);">
          <div style="padding: 30px 30px 20px; text-align: center; border-bottom: 1px solid rgba(79,70,229,0.2);">
            <div style="display: inline-block; background: linear-gradient(135deg, #4f46e5, #7c3aed); padding: 15px 25px; border-radius: 12px; margin-bottom: 10px;">
              <span style="font-size: 28px; font-weight: 800; color: #ffffff;">BEDAYA</span>
              <span style="font-size: 20px; font-weight: 400; color: #a78bfa; margin-right: 8px;">مركز بداية</span>
            </div>
            <div style="margin-top: 8px;"><span style="font-size: 13px; color: #94a3b8;">للتدخل المبكر والتأهيل</span></div>
          </div>
          <div style="padding: 30px; background: rgba(15, 23, 42, 0.6);">
            <div style="background: rgba(16, 185, 129, 0.15); border-right: 4px solid #10b981; padding: 15px 20px; border-radius: 8px; margin-bottom: 25px;">
              <h2 style="color: #e2e8f0; font-size: 20px; margin: 0; font-weight: 700;">✅ تم تغيير كلمة المرور بنجاح</h2>
            </div>
            <div style="background: rgba(30, 41, 59, 0.5); border-radius: 12px; padding: 20px; border: 1px solid rgba(79,70,229,0.1);">
              <p style="color: #e2e8f0; font-size: 16px; line-height: 1.8;">
                تم تغيير كلمة المرور الخاصة بحسابك في <strong style="color: #818cf8;">مركز بداية للتدخل المبكر والتأهيل</strong> بنجاح.
              </p>
              <p style="color: #94a3b8; font-size: 14px; line-height: 1.8; margin-top: 10px;">
                إذا لم تكن أنت من قام بهذا التغيير، يرجى التواصل معنا فوراً عبر البريد الإلكتروني أو الهاتف.
              </p>
              <div style="text-align: center; margin-top: 20px;">
                <a href="${req.protocol}://${req.get('host')}/login" style="display: inline-block; padding: 12px 30px; background: linear-gradient(135deg, #10b981, #059669); color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: 700; font-size: 16px;">
                  الذهاب إلى صفحة تسجيل الدخول
                </a>
              </div>
            </div>
          </div>
          <div style="padding: 20px 30px; text-align: center; border-top: 1px solid rgba(79,70,229,0.1); background: rgba(15, 23, 42, 0.4);">
            <p style="color: #64748b; font-size: 12px; margin: 0;">© 2025 مركز بداية للتدخل المبكر والتأهيل | جميع الحقوق محفوظة</p>
          </div>
        </div>
      </body>
      </html>
    `;

    await sendEmail(email, 'تم تغيير كلمة المرور - مركز بداية', confirmHtml);

    res.json({
      success: true,
      message: 'تم إعادة تعيين كلمة المرور بنجاح'
    });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء إعادة تعيين كلمة المرور' });
  }
});

// ============================================
// USER MANAGEMENT (Admin Only)
// ============================================
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const usersSnapshot = await db.collection('users')
      .orderBy('createdAt', 'desc')
      .get();

    const users = [];
    usersSnapshot.forEach(doc => {
      const data = doc.data();
      delete data.password;
      users.push({ id: doc.id, ...data });
    });

    res.json(users);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Error fetching users' });
  }
});

app.put('/api/admin/users/:id', authenticateAdmin, [
  body('fullName').optional().notEmpty().withMessage('الاسم مطلوب'),
  body('email').optional().isEmail().withMessage('بريد إلكتروني غير صحيح'),
  body('phone').optional(),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { fullName, email, phone } = req.body;
    const userId = req.params.id;

    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (userDoc.data().isAdmin) {
      return res.status(403).json({ error: 'لا يمكن تعديل حساب المدير' });
    }

    const updateData = {};
    if (fullName) updateData.fullName = fullName;
    if (email) {
      const existingSnapshot = await db.collection('users')
        .where('email', '==', email)
        .get();
      if (!existingSnapshot.empty) {
        const existingDoc = existingSnapshot.docs[0];
        if (existingDoc.id !== userId) {
          return res.status(400).json({ error: 'البريد الإلكتروني مستخدم بالفعل' });
        }
      }
      updateData.email = email;
    }
    if (phone !== undefined) updateData.phone = phone;
    updateData.updatedAt = new Date().toISOString();

    await userRef.update(updateData);

    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    if (token) {
      await blacklistToken(token);
    }

    res.json({
      success: true,
      message: 'تم تحديث بيانات المستخدم بنجاح'
    });
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث المستخدم' });
  }
});

app.delete('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    const userDoc = await db.collection('users').doc(userId).get();
    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }
    if (userDoc.data().isAdmin) {
      return res.status(403).json({ error: 'لا يمكن حذف حساب المدير' });
    }
    await db.collection('users').doc(userId).delete();
    res.json({ success: true, message: 'تم حذف المستخدم بنجاح' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء حذف المستخدم' });
  }
});

// ============================================
// BOOKING ROUTES
// ============================================
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

    sendTelegramNotification(
      `📅 <b>حجز جديد</b>\n\n` +
      `👤 الاسم: ${fullName}\n` +
      `📱 التليفون: ${phone}\n` +
      `📆 التاريخ: ${date}\n` +
      `🕐 الوقت: ${time}`,
      'booking'
    ).catch(console.error);

    res.status(201).json({
      success: true,
      booking: { id: docRef.id, ...booking }
    });
  } catch (error) {
    console.error('Booking error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء الحجز' });
  }
});

// ============================================
// CONTACT ROUTES
// ============================================
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

    const contactData = {
      name,
      email,
      phone,
      message,
      sentAt: new Date().toISOString()
    };
    await db.collection('contacts').add(contactData);

    const adminHtml = `
      <!DOCTYPE html>
      <html dir="rtl" lang="ar">
      <head><meta charset="UTF-8"><title>رسالة جديدة</title></head>
      <body style="font-family: 'Cairo', Arial, sans-serif; direction: rtl; text-align: right; background-color: #0f172a; margin: 0; padding: 0;">
        <div style="max-width: 600px; margin: 20px auto; background: linear-gradient(135deg, #1e1b4b, #312e81); border-radius: 16px; overflow: hidden; box-shadow: 0 20px 60px rgba(0,0,0,0.5); border: 1px solid rgba(79,70,229,0.2);">
          <div style="padding: 30px 30px 20px; text-align: center; border-bottom: 1px solid rgba(79,70,229,0.2);">
            <div style="display: inline-block; background: linear-gradient(135deg, #4f46e5, #7c3aed); padding: 15px 25px; border-radius: 12px; margin-bottom: 10px;">
              <span style="font-size: 28px; font-weight: 800; color: #ffffff;">BEDAYA</span>
              <span style="font-size: 20px; font-weight: 400; color: #a78bfa; margin-right: 8px;">مركز بداية</span>
            </div>
            <div style="margin-top: 8px;"><span style="font-size: 13px; color: #94a3b8;">للتدخل المبكر والتأهيل</span></div>
          </div>
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
          <div style="padding: 20px 30px; text-align: center; border-top: 1px solid rgba(79,70,229,0.1); background: rgba(15, 23, 42, 0.4);">
            <p style="color: #64748b; font-size: 12px; margin: 0;">© 2025 مركز بداية للتدخل المبكر والتأهيل | جميع الحقوق محفوظة</p>
          </div>
        </div>
      </body>
      </html>
    `;
    
    sendEmail(process.env.ADMIN_EMAIL, 'رسالة جديدة من مركز بداية', adminHtml).catch(console.error);
    
    sendTelegramNotification(
      `📧 <b>رسالة جديدة</b>\n\n` +
      `👤 الاسم: ${name}\n` +
      `📧 البريد: ${email}\n` +
      `📱 التليفون: ${phone}\n` +
      `💬 الرسالة: ${message}`,
      'contact'
    ).catch(console.error);

    res.json({
      success: true,
      message: 'تم إرسال الرسالة بنجاح'
    });
  } catch (error) {
    console.error('Contact error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء إرسال الرسالة' });
  }
});

// ============================================
// RESULTS ROUTES (Public facing)
// ============================================
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

// ============================================
// ADMIN DASHBOARD ROUTES - MODIFIED (no adminName)
// ============================================

// --- Stats ---
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const adminUsername = req.user.adminUsername || 'admin';
    
    // Filter sales by adminUsername only
    let salesSnapshot = await db.collection('sales')
      .where('date', '==', today)
      .where('adminUsername', '==', adminUsername)
      .get();
    
    let todaySales = 0;
    salesSnapshot.forEach(doc => {
      todaySales += doc.data().amount || 0;
    });

    // Shared collections (not filtered by admin)
    let bookingsSnapshot = await db.collection('bookings').get();
    let messagesSnapshot = await db.collection('messages').get();

    res.json({
      todaySales,
      totalBookings: bookingsSnapshot.size || 0,
      totalMessages: messagesSnapshot.size || 0,
      adminUsername
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.json({ todaySales: 0, totalBookings: 0, totalMessages: 0 });
  }
});

// --- Sales Chart (Filtered by AdminUsername only) ---
app.get('/api/admin/sales-chart', authenticateAdmin, async (req, res) => {
  try {
    const adminUsername = req.user.adminUsername || 'admin';
    
    let salesSnapshot = await db.collection('sales')
      .where('adminUsername', '==', adminUsername)
      .orderBy('date', 'desc')
      .limit(30)
      .get();

    const salesData = [];
    salesSnapshot.forEach(doc => {
      const data = doc.data();
      salesData.push({
        date: data.date || new Date().toISOString().split('T')[0],
        amount: data.amount || 0
      });
    });

    res.json(salesData.reverse());
  } catch (error) {
    console.error('Sales chart error:', error);
    res.json([]);
  }
});

// --- Sales CRUD (Filtered by AdminUsername only) ---
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
    const adminUsername = req.user.adminUsername || 'admin';

    const sale = {
      customer,
      amount: parseFloat(amount),
      date: today,
      adminUsername,
      createdAt: new Date().toISOString()
    };

    const docRef = await db.collection('sales').add(sale);
    res.status(201).json({ success: true, sale: { id: docRef.id, ...sale } });
  } catch (error) {
    console.error('Add sale error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء تسجيل البيع' });
  }
});

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
    const saleId = req.params.id;
    const adminUsername = req.user.adminUsername || 'admin';

    const saleRef = db.collection('sales').doc(saleId);
    const saleDoc = await saleRef.get();

    if (!saleDoc.exists) {
      return res.status(404).json({ error: 'Sale not found' });
    }

    // Verify this sale belongs to the current admin
    const saleData = saleDoc.data();
    if (saleData.adminUsername !== adminUsername) {
      return res.status(403).json({ error: 'You do not have permission to update this sale' });
    }

    await saleRef.update({
      customer,
      amount: parseFloat(amount),
      updatedAt: new Date().toISOString()
    });

    res.json({ success: true, message: 'تم تحديث البيع بنجاح' });
  } catch (error) {
    console.error('Update sale error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث البيع' });
  }
});

app.get('/api/admin/sales', authenticateAdmin, async (req, res) => {
  try {
    const adminUsername = req.user.adminUsername || 'admin';
    
    let salesSnapshot = await db.collection('sales')
      .where('adminUsername', '==', adminUsername)
      .orderBy('createdAt', 'desc')
      .get();

    const sales = [];
    salesSnapshot.forEach(doc => {
      sales.push({ id: doc.id, ...doc.data() });
    });

    res.json(sales);
  } catch (error) {
    console.error('Get sales error:', error);
    res.json([]);
  }
});

app.delete('/api/admin/sales/:id', authenticateAdmin, async (req, res) => {
  try {
    const saleId = req.params.id;
    const adminUsername = req.user.adminUsername || 'admin';

    const saleRef = db.collection('sales').doc(saleId);
    const saleDoc = await saleRef.get();

    if (!saleDoc.exists) {
      return res.status(404).json({ error: 'Sale not found' });
    }

    // Verify this sale belongs to the current admin
    const saleData = saleDoc.data();
    if (saleData.adminUsername !== adminUsername) {
      return res.status(403).json({ error: 'You do not have permission to delete this sale' });
    }

    await saleRef.delete();
    res.json({ success: true });
  } catch (error) {
    console.error('Delete sale error:', error);
    res.status(500).json({ error: 'Error deleting sale' });
  }
});

// --- Bookings (Shared - All admins see all) ---
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

app.delete('/api/admin/bookings/:id', authenticateAdmin, async (req, res) => {
  try {
    await db.collection('bookings').doc(req.params.id).delete();
    res.json({ success: true });
  } catch (error) {
    console.error('Delete booking error:', error);
    res.status(500).json({ error: 'Error deleting booking' });
  }
});

// --- Results (Shared - All admins see all) ---
app.post('/api/admin/results/upload', authenticateAdmin, upload.single('file'), async (req, res) => {
  try {
    const { phone } = req.body;
    const file = req.file;

    if (!file) return res.status(400).json({ error: 'الملف مطلوب' });
    if (!phone) return res.status(400).json({ error: 'رقم الهاتف مطلوب' });

    // Get the original file extension
    const originalName = file.originalname || 'file';
    const extension = originalName.includes('.') ? originalName.split('.').pop() : '';
    const fileName = `Result-Center-Bedaya${extension ? '.' + extension : ''}`;

    const result = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream({
        folder: 'results',
        public_id: `Result-Center-Bedaya_${Date.now()}`,
        resource_type: 'auto',
        use_filename: true,
        unique_filename: false,
        overwrite: true
      }, (error, result) => {
        if (error) reject(error);
        else resolve(result);
      });
      uploadStream.end(file.buffer);
    });

    const url = result.secure_url;

    const existingSnapshot = await db.collection('results')
      .where('phone', '==', phone)
      .get();

    let resultId;
    if (!existingSnapshot.empty) {
      const doc = existingSnapshot.docs[0];
      resultId = doc.id;
      await db.collection('results').doc(doc.id).update({
        url,
        fileName: fileName,
        updatedAt: new Date().toISOString()
      });
    } else {
      const newDoc = await db.collection('results').add({
        phone,
        url,
        fileName: fileName,
        createdAt: new Date().toISOString()
      });
      resultId = newDoc.id;
    }

    res.json({ success: true, url, id: resultId, message: 'تم رفع النتيجة بنجاح' });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء رفع الملف' });
  }
});

app.put('/api/admin/results/:id', authenticateAdmin, upload.single('file'), async (req, res) => {
  try {
    const { phone } = req.body;
    const file = req.file;
    const resultId = req.params.id;

    if (!phone) return res.status(400).json({ error: 'رقم الهاتف مطلوب' });

    const resultRef = db.collection('results').doc(resultId);
    const resultDoc = await resultRef.get();

    if (!resultDoc.exists) {
      return res.status(404).json({ error: 'Result not found' });
    }

    let updateData = { phone, updatedAt: new Date().toISOString() };

    if (file) {
      // Get the original file extension
      const originalName = file.originalname || 'file';
      const extension = originalName.includes('.') ? originalName.split('.').pop() : '';
      const fileName = `Result-Center-Bedaya${extension ? '.' + extension : ''}`;

      const result = await new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream({
          folder: 'results',
          public_id: `Result-Center-Bedaya_${Date.now()}`,
          resource_type: 'auto',
          use_filename: true,
          unique_filename: false,
          overwrite: true
        }, (error, result) => {
          if (error) reject(error);
          else resolve(result);
        });
        uploadStream.end(file.buffer);
      });
      updateData.url = result.secure_url;
      updateData.fileName = fileName;
    }

    await resultRef.update(updateData);

    res.json({ success: true, message: 'تم تحديث النتيجة بنجاح' });
  } catch (error) {
    console.error('Update result error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث النتيجة' });
  }
});

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

app.delete('/api/admin/results/:id', authenticateAdmin, async (req, res) => {
  try {
    await db.collection('results').doc(req.params.id).delete();
    res.json({ success: true });
  } catch (error) {
    console.error('Delete result error:', error);
    res.status(500).json({ error: 'Error deleting result' });
  }
});

// --- Messages (Shared - All admins see all) ---
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

// --- Contacts (Shared - All admins see all) ---
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

app.delete('/api/admin/contacts/:id', authenticateAdmin, async (req, res) => {
  try {
    await db.collection('contacts').doc(req.params.id).delete();
    res.json({ success: true });
  } catch (error) {
    console.error('Delete contact error:', error);
    res.status(500).json({ error: 'Error deleting contact' });
  }
});

// --- Send Email (Shared) ---
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

    const mailHtml = `
      <!DOCTYPE html>
      <html dir="rtl" lang="ar">
      <head><meta charset="UTF-8"><title>رسالة من مركز بداية</title></head>
      <body style="font-family: 'Cairo', Arial, sans-serif; direction: rtl; text-align: right; background-color: #0f172a; margin: 0; padding: 0;">
        <div style="max-width: 600px; margin: 20px auto; background: linear-gradient(135deg, #1e1b4b, #312e81); border-radius: 16px; overflow: hidden; box-shadow: 0 20px 60px rgba(0,0,0,0.5); border: 1px solid rgba(79,70,229,0.2);">
          <div style="padding: 30px 30px 20px; text-align: center; border-bottom: 1px solid rgba(79,70,229,0.2);">
            <div style="display: inline-block; background: linear-gradient(135deg, #4f46e5, #7c3aed); padding: 15px 25px; border-radius: 12px; margin-bottom: 10px;">
              <span style="font-size: 28px; font-weight: 800; color: #ffffff;">BEDAYA</span>
              <span style="font-size: 20px; font-weight: 400; color: #a78bfa; margin-right: 8px;">مركز بداية</span>
            </div>
            <div style="margin-top: 8px;"><span style="font-size: 13px; color: #94a3b8;">للتدخل المبكر والتأهيل</span></div>
          </div>
          <div style="padding: 30px; background: rgba(15, 23, 42, 0.6);">
            <div style="background: rgba(79, 70, 229, 0.08); border-right: 4px solid #4f46e5; padding: 15px 20px; border-radius: 8px; margin-bottom: 25px;">
              <h2 style="color: #e2e8f0; font-size: 20px; margin: 0; font-weight: 700;">📧 رسالة من مركز بداية</h2>
            </div>
            <div style="background: rgba(30, 41, 59, 0.5); border-radius: 12px; padding: 20px; border: 1px solid rgba(79,70,229,0.1);">
              <div style="color: #e2e8f0; line-height: 2; font-size: 16px; white-space: pre-wrap;">${message}</div>
            </div>
          </div>
          <div style="padding: 20px 30px; text-align: center; border-top: 1px solid rgba(79,70,229,0.1); background: rgba(15, 23, 42, 0.4);">
            <p style="color: #64748b; font-size: 12px; margin: 0;">© 2025 مركز بداية للتدخل المبكر والتأهيل | جميع الحقوق محفوظة</p>
          </div>
        </div>
      </body>
      </html>
    `;

    await sendEmail(email, 'رسالة من مركز بداية للتدخل المبكر والتأهيل', mailHtml);

    await db.collection('messages').add({
      email,
      message,
      sentAt: new Date().toISOString()
    });

    res.json({ success: true, message: 'تم إرسال الرسالة بنجاح' });
  } catch (error) {
    console.error('Send email error:', error);
    res.status(500).json({ error: 'حدث خطأ أثناء إرسال الرسالة' });
  }
});

app.delete('/api/admin/messages/:id', authenticateAdmin, async (req, res) => {
  try {
    await db.collection('messages').doc(req.params.id).delete();
    res.json({ success: true });
  } catch (error) {
    console.error('Delete message error:', error);
    res.status(500).json({ error: 'Error deleting message' });
  }
});

// ============================================
// SERVE HTML PAGES
// ============================================
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

app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
});

// ============================================
// START SERVER
// ============================================
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`🌐 http://localhost:${PORT}`);
  console.log(`📊 Max concurrent requests: ${MAX_CONCURRENT_REQUESTS}`);
  console.log(`⏱️ Request timeout: 30 seconds`);
  console.log(`🔐 Token blacklist system is active`);
});
