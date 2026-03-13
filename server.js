const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const swaggerUi = require('swagger-ui-express');
const connectDB = require('./config/database');
require('dotenv').config();
const User = require('./models/User');
const swaggerSpecs = require('./config/swagger');

const app = express();
const isProduction = process.env.NODE_ENV === 'production';
const PORT = process.env.PORT || 5000;

const normalizeBaseUrl = (value) => value.replace(/\/+$/, '');
const resolveBaseUrl = (port) => {
  const envUrl =
    process.env.API_BASE_URL || process.env.BASE_URL || process.env.PUBLIC_URL;
  if (envUrl) return normalizeBaseUrl(envUrl);

  const host = process.env.HOST || 'localhost';
  const hasPort = /:\d+$/.test(host);
  const protocol =
    process.env.HTTPS === 'true' || process.env.USE_HTTPS === 'true'
      ? 'https'
      : 'http';
  const portSuffix = hasPort ? '' : `:${port}`;
  return `${protocol}://${host}${portSuffix}`;
};
const baseUrl = resolveBaseUrl(PORT);
const withBaseUrl = (pathValue) =>
  `${baseUrl}${pathValue.startsWith('/') ? '' : '/'}${pathValue}`;

const parseAllowedOrigins = (value) => {
  if (!value) return [];
  return value
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
};

const allowedOrigins = parseAllowedOrigins(process.env.FRONTEND_URL);

// ==================== MIDDLEWARE ====================
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: (origin, callback) => {
      // Native mobile clients / curl may not send Origin.
      if (!origin) return callback(null, true);
      if (!isProduction) return callback(null, true);

      if (allowedOrigins.length === 0) {
        return callback(
          new Error('CORS blocked: FRONTEND_URL is not configured in production')
        );
      }

      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error(`CORS blocked for origin: ${origin}`));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  })
);

// ==================== DATABASE ====================
connectDB();

// ==================== STARTUP SEEDING ====================
(async () => {
  try {
    const existingSuperuser = await User.findOne({ role: 'superuser' });
    if (!existingSuperuser) {
      const seededEmail = process.env.SUPERUSER_EMAIL;
      const seededPassword = process.env.SUPERUSER_PASSWORD;

      if (isProduction && (!seededEmail || !seededPassword)) {
        console.warn(
          'No superuser exists. Skipping auto-create in production because SUPERUSER_EMAIL/SUPERUSER_PASSWORD are not set.'
        );
        return;
      }

      console.log('No superuser found. Creating superuser...');
      const email = seededEmail || 'admin@admin.com';
      const password = seededPassword || 'admin123';
      await User.create({
        Name: 'Admin User',
        firstName: 'Admin',
        lastName: 'User',
        email,
        password,
        role: 'superuser',
        isEmailVerified: true,
      });
      console.log(`Superuser created. Email: ${email}`);
    } else {
      console.log('Superuser already exists. Skipping seeding.');
    }
  } catch (err) {
    console.error('Failed to seed superuser:', err.message);
  }
})();

// ==================== STARTUP THERAPIST SEEDING ====================
(async () => {
  try {
    const predefinedUsers = [
      {
        Name: 'DEVELOPMENTAL THERAPY UNIT',
        firstName: 'Developmental',
        lastName: 'Therapy Unit',
        email: 'developmental.therapy@hospital.com',
        password: 'therapy123',
        role: 'superuser',
        isEmailVerified: true,
      },
      {
        Name: 'G BLOCK OPD',
        firstName: 'G Block',
        lastName: 'OPD',
        email: 'gblock.opd@hospital.com',
        password: 'opd123',
        role: 'superuser',
        isEmailVerified: true,
      },
    ];

    for (const seedUser of predefinedUsers) {
      const existingUser = await User.findOne({ email: seedUser.email });
      if (existingUser) {
        console.log(`Seed user already exists. Skipping: ${seedUser.email}`);
        continue;
      }

      await User.create(seedUser);
      console.log(`Seed user created: ${seedUser.email}`);
    }
  } catch (err) {
    console.error('Failed to seed predefined therapist users:', err.message);
  }
})();

// ==================== SWAGGER DOCUMENTATION ====================
app.use(
  '/api/docs',
  swaggerUi.serve,
  swaggerUi.setup(swaggerSpecs, {
    explorer: true,
    customCss: '.swagger-ui .topbar { display: none }',
    customSiteTitle: 'DOT Therapy API Documentation',
  })
);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'DOT Therapy API is running!',
    timestamp: new Date().toISOString(),
    documentation: '/api/docs',
  });
});

// ==================== API ROUTES ====================
const AuthRoutes = require('./routes/api/AuthRoutes');
app.use('/api/auth', AuthRoutes);
console.log(`Auth routes loaded at ${withBaseUrl('/api/auth')}`);

const AdminRoutes = require('./routes/api/adminRoutes');
app.use('/api/admin', AdminRoutes);
console.log(`Admin routes loaded at ${withBaseUrl('/api/admin')}`);

const TherapistRoutes = require('./routes/api/therapistRoutes');
app.use('/api/therapist', TherapistRoutes);
console.log(`Therapist routes loaded at ${withBaseUrl('/api/therapist')}`);

const ChildRoutes = require('./routes/api/ChildRoutes');
app.use('/api/child', ChildRoutes);
console.log(`Child routes loaded at ${withBaseUrl('/api/child')}`);

const GamesRoutes = require('./routes/api/gamesRoutes');
app.use('/games', GamesRoutes);
app.use('/api/games', GamesRoutes);
console.log(
  `Games routes loaded at ${withBaseUrl('/games')} and ${withBaseUrl('/api/games')}`
);

// Serve uploaded files from /uploads
app.use('/uploads', express.static(path.join(process.cwd(), 'uploads')));
console.log(`Serving uploaded files from ${withBaseUrl('/uploads')}`);

// ==================== ERROR HANDLERS ====================
app.use((err, req, res, next) => {
  console.error('Error:', err);

  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map((e) => ({
      field: e.path,
      message: e.message,
    }));
    return res
      .status(400)
      .json({ success: false, message: 'Validation Error', errors });
  }

  if (err.name === 'CastError') {
    return res.status(400).json({ success: false, message: 'Invalid ID format' });
  }

  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }

  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({ success: false, message: 'Token expired' });
  }

  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    return res
      .status(400)
      .json({ success: false, message: `${field} already exists` });
  }

  return res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Internal Server Error',
    error: process.env.NODE_ENV === 'development' ? err.stack : {},
  });
});

// 404 handler (MUST be last)
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: `Route '${req.originalUrl}' not found`,
    availableRoutes: {
      public: ['/api/health', '/api/docs'],
      auth: ['/api/auth/register', '/api/auth/login', '/api/auth/profile'],
      protected: ['All other routes require authentication'],
    },
    documentation: 'Visit /api/docs for complete API documentation',
  });
});

// ==================== START SERVER ====================
if (isProduction) {
  const clientBuildPath = path.join(__dirname, '..', 'frontend', 'build');
  if (fs.existsSync(clientBuildPath)) {
    app.use(express.static(clientBuildPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(clientBuildPath, 'index.html'));
    });
  }
}

app.listen(PORT, () => {
  console.log(`Server listening at ${baseUrl}`);
  console.log(`API docs available at ${withBaseUrl('/api/docs')}`);
  console.log(`Health check available at ${withBaseUrl('/api/health')}`);
  if (isProduction) {
    console.log(
      `Allowed CORS origins: ${
        allowedOrigins.length ? allowedOrigins.join(', ') : '[none configured]'
      }`
    );
  }
});
