require('dotenv').config();

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const flash = require('connect-flash');
const path = require('path');
const cors = require('cors');

const { parseSubsets, getUserSubset, getCookieConfigForSubset } = require('./config/subsets');

const app = express();

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../views'));

// Middleware
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../public')));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-session-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Flash messages
app.use(flash());

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Parse subsets from environment
const subsets = parseSubsets();

// Passport serialization
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// Google OAuth Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback'
  },
  (accessToken, refreshToken, profile, done) => {
    const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
    const user = {
      id: profile.id,
      email: email,
      displayName: profile.displayName,
      photo: profile.photos && profile.photos[0] ? profile.photos[0].value : null
    };
    return done(null, user);
  }
));

// Middleware to pass flash messages to views
app.use((req, res, next) => {
  res.locals.error = req.flash('error');
  res.locals.success = req.flash('success');
  next();
});

// Store return_url in session
const storeReturnUrl = (req, res, next) => {
  if (req.query.return_url) {
    req.session.return_url = req.query.return_url;
  }
  next();
};

// Home / Login page
app.get('/', storeReturnUrl, (req, res) => {
  // If user is already logged in, process cookies and redirect
  if (req.isAuthenticated()) {
    return res.redirect('/process-auth');
  }
  
  const returnUrl = req.session.return_url || req.query.return_url || '';
  res.render('login', { 
    returnUrl,
    user: req.user
  });
});

// Login page (alternative route)
app.get('/login', storeReturnUrl, (req, res) => {
  if (req.isAuthenticated()) {
    return res.redirect('/process-auth');
  }
  
  const returnUrl = req.session.return_url || req.query.return_url || '';
  res.render('login', { 
    returnUrl,
    user: req.user
  });
});

// Google OAuth routes
app.get('/auth/google', storeReturnUrl, (req, res, next) => {
  const authOptions = {
    scope: ['profile', 'email'],
    prompt: 'select_account' // Always show account selection
  };
  
  passport.authenticate('google', authOptions)(req, res, next);
});

app.get('/auth/google/callback',
  passport.authenticate('google', { 
    failureRedirect: '/login',
    failureFlash: 'Authentication failed. Please try again.'
  }),
  (req, res) => {
    res.redirect('/process-auth');
  }
);

// Process authentication and set cookies
app.get('/process-auth', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }

  const email = req.user.email;
  
  // Find user's subset
  const userSubset = getUserSubset(email, subsets);
  
  if (!userSubset) {
    req.flash('error', 'This email is not authorized to access this application.');
    return res.render('unauthorized', {
      email: email,
      returnUrl: req.session.return_url || ''
    });
  }

  // Get cookie configuration for the subset
  const cookieConfigs = getCookieConfigForSubset(userSubset.name);
  
  // Generate and set JWT cookies
  cookieConfigs.forEach(config => {
    const payload = {
      sub: req.user.id,
      email: email,
      name: req.user.displayName,
      subset: userSubset.name,
      ...config.additionalClaims
    };

    const token = jwt.sign(
      payload,
      config.secret,
      {
        algorithm: config.algorithm || 'HS256',
        expiresIn: config.expiresIn || '24h'
      }
    );

    // Set cookie with proper options
    const cookieOptions = {
      httpOnly: config.httpOnly !== false,
      secure: process.env.NODE_ENV === 'production',
      maxAge: config.maxAge || 24 * 60 * 60 * 1000, // 24 hours default
      path: config.path || '/',
      sameSite: config.sameSite || 'lax'
    };

    if (config.domain) {
      cookieOptions.domain = config.domain;
    }

    res.cookie(config.cookieName, token, cookieOptions);
  });

  // Redirect to return_url or show success
  const returnUrl = req.session.return_url;
  
  if (returnUrl) {
    // Clear the stored return_url
    delete req.session.return_url;
    return res.redirect(returnUrl);
  }

  res.render('success', {
    user: req.user,
    subset: userSubset.name,
    cookiesSet: cookieConfigs.map(c => c.cookieName)
  });
});

// Try with different account
app.get('/try-different-account', (req, res) => {
  // Logout but preserve return_url
  const returnUrl = req.session.return_url;
  
  req.logout((err) => {
    if (err) {
      console.error('Logout error:', err);
    }
    
    // Restore return_url
    req.session.return_url = returnUrl;
    
    // Redirect to Google OAuth with prompt for account selection
    res.redirect('/auth/google');
  });
});

// Logout
app.get('/logout', (req, res) => {
  // Clear all JWT cookies
  const allCookieNames = getAllCookieNames();
  allCookieNames.forEach(cookieName => {
    res.clearCookie(cookieName);
  });

  req.logout((err) => {
    if (err) {
      console.error('Logout error:', err);
    }
    const returnUrl = req.session.return_url || req.query.return_url;
    req.session.destroy();
    
    if (returnUrl) {
      return res.redirect(returnUrl);
    }
    res.redirect('/');
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Helper function to get all configured cookie names
function getAllCookieNames() {
  const cookieNames = new Set();
  const cookieConfigPrefix = 'SUBSET_';
  const cookieConfigSuffix = '_COOKIES';
  
  Object.keys(process.env).forEach(key => {
    if (key.startsWith(cookieConfigPrefix) && key.endsWith(cookieConfigSuffix)) {
      const cookiesStr = process.env[key];
      if (cookiesStr) {
        cookiesStr.split(',').forEach(cookieName => {
          cookieNames.add(cookieName.trim());
        });
      }
    }
  });
  
  return Array.from(cookieNames);
}

// Error handling
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).render('error', {
    message: 'An unexpected error occurred',
    error: process.env.NODE_ENV === 'development' ? err : {}
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).render('error', {
    message: 'Page not found',
    error: {}
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Auth JWT Gateway running on port ${PORT}`);
  console.log(`Subsets configured: ${Object.keys(subsets).join(', ') || 'None'}`);
});
