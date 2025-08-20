require('dotenv').config();
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const path = require('path');
const passport = require('passport');

// Import route handlers
const authRoutes = require('./routes/authRoutes');
const apiKeyRoutes = require('./routes/apiKeyRoutes');
const adminRoutes = require('./routes/adminRoutes');
const twoFactorRoutes = require('./routes/twoFactorRoutes');
const clientRoutes = require('./routes/clientRoutes');
const oauthRoutes = require('./routes/oauthRoutes');
const connectDB = require('./config/db');
require('./config/passport');

const app = express();
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Connect to Database
connectDB();

// --- CORE MIDDLEWARE
app.use(helmet());
app.use(express.json()); 
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser()); 

// --- VIEW ENGINE & STATIC FILES
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

// CORS Configuration
app.use(
  cors({
    origin: 'http://localhost:3000',
    credentials: true,
  })
);

// Session Configuration
app.use(
  session({
    secret: process.env.JWT_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      secure: NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 60 * 60 * 1000,
    },
  })
);

// Passport Initialization
app.use(passport.initialize());

// Rate Limiter
const authLimiter = rateLimit({
  windowMs: 900000,
  max: 100,
});


// --- ROUTES 
app.get('/', (req, res) => res.json({ message: 'NeonTek Accounts API - running' }));
app.use('/api/auth', authLimiter, authRoutes);
app.use('/api/keys', authLimiter, apiKeyRoutes);
app.use('/api/admin', authLimiter, adminRoutes);
app.use('/api/2fa', authLimiter, twoFactorRoutes);
app.use('/api/clients', authLimiter, clientRoutes);
app.use('/oauth', oauthRoutes);

// Error Handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ message: err.message || 'Server error' });
});

// Start Server
app.listen(PORT, () =>
  console.log(`Server listening on port ${PORT} in ${NODE_ENV} mode`)
);