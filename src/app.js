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

const { parseSubsets, getUserSubset, getCookieConfigForSubset, validateConfiguration } = require('./config/subsets');

const app = express();

// Validate configuration at startup
const configValidation = validateConfiguration();
if (configValidation.errors.length > 0) {
  console.error('Configuration errors:');
  configValidation.errors.forEach(err => console.error(`  - ${err}`));
  process.exit(1);
}
if (configValidation.warnings.length > 0) {
  console.warn('Configuration warnings:');
  configValidation.warnings.forEach(warn => console.warn(`  - ${warn}`));
}

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../views'));

// Trust proxy when behind reverse proxy
app.set('trust proxy', 1);

// CORS configuration - restrict origins in production
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : [];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    // In development, allow all origins
    if (process.env.NODE_ENV !== 'production') {
      return callback(null, true);
    }
    
    // In production, check against allowed origins
    // If no origins configured, allow all (warning is logged at startup via validateConfiguration)
    if (allowedOrigins.length === 0) {
      return callback(null, true);
    }
    
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../public')));

// Ensure we always have a session secret. In production, SESSION_SECRET must be set.
const isProduction = process.env.NODE_ENV === 'production';
let sessionSecret = process.env.SESSION_SECRET;

if (!sessionSecret) {
  if (isProduction) {
    console.error('SESSION_SECRET environment variable is required in production.');
    process.exit(1);
  } else {
    // Development-only fallback to avoid runtime errors; do NOT use in production.
    sessionSecret = 'insecure-dev-session-secret-change-me';
    console.warn('SESSION_SECRET is not set. Using an insecure default session secret for development only.');
  }
}

// Session configuration
app.use(session({
  name: 'auth.sid',
  secret: sessionSecret,
  resave: true,
  saveUninitialized: true,
  cookie: {
    secure: isProduction,
    httpOnly: true,
    sameSite: 'lax',
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

// Validate return_url to prevent open redirect attacks
// Module-level flags to track if warnings have been logged (to avoid spamming logs)
let redirectDomainsProductionWarningLogged = false;
let redirectDomainsDevWarningLogged = false;

const isValidReturnUrl = (url) => {
  if (!url) return false;
  
  // Get allowed domains from environment
  const allowedDomains = process.env.ALLOWED_REDIRECT_DOMAINS 
    ? process.env.ALLOWED_REDIRECT_DOMAINS.split(',').map(d => d.trim().toLowerCase())
    : [];
  
  try {
    const parsedUrl = new URL(url);
    
    // Only allow http and https protocols
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      return false;
    }
    
    // If no allowed domains configured
    if (allowedDomains.length === 0) {
      if (isProduction) {
        // In production, log a warning once and reject absolute URLs when no domains are configured
        if (!redirectDomainsProductionWarningLogged) {
          console.warn('WARNING: ALLOWED_REDIRECT_DOMAINS is not configured in production. All absolute redirect URLs will be rejected. Only relative URLs (starting with /) will be allowed.');
          redirectDomainsProductionWarningLogged = true;
        }
        return false;
      } else {
        // In development, allow all but log a warning (only once)
        if (!redirectDomainsDevWarningLogged) {
          console.warn('WARNING: ALLOWED_REDIRECT_DOMAINS is not configured. All redirect URLs are allowed in development mode.');
          redirectDomainsDevWarningLogged = true;
        }
        return true;
      }
    }
    
    // Check if the domain is in the allowed list
    const hostname = parsedUrl.hostname.toLowerCase();
    return allowedDomains.some(domain => {
      // Support wildcard subdomains (e.g., .example.com matches sub.example.com)
      if (domain.startsWith('.')) {
        return hostname === domain.slice(1) || hostname.endsWith(domain);
      }
      return hostname === domain;
    });
  } catch {
    // If URL parsing fails, treat it as a relative URL.
    // Only allow a single leading slash (e.g., "/path"), and reject
    // protocol-relative or backslash-prefixed URLs like "//evil.com" or "/\evil.com".
    if (url[0] !== '/') {
      return false;
    }
    if (url.length >= 2 && (url[1] === '/' || url[1] === '\\')) {
      return false;
    }
    return true;
  }
};

// Store return_url in session (with validation)
const storeReturnUrl = (req, res, next) => {
  if (req.query.return_url) {
    if (isValidReturnUrl(req.query.return_url)) {
      req.session.return_url = req.query.return_url;
      return req.session.save((err) => {
        if (err) console.error('Session save error:', err);
        next();
      });
    } else {
      console.warn(`Invalid return_url rejected: ${req.query.return_url}`);
    }
  }
  next();
};

// Shared login page handler
const loginPageHandler = (req, res) => {
  // If user is already logged in, process cookies and redirect
  if (req.isAuthenticated()) {
    return res.redirect('/process-auth');
  }
  
  const returnUrl = req.session.return_url || req.query.return_url || '';
  res.render('login', { 
    returnUrl,
    user: req.user
  });
};

// Home / Login page
app.get('/', storeReturnUrl, loginPageHandler);

// Login page (alternative route)
app.get('/login', storeReturnUrl, loginPageHandler);

// Google OAuth routes
app.get('/auth/google', storeReturnUrl, (req, res, next) => {
  // Get return_url from session or query and pass it via OAuth state parameter
  const returnUrl = req.session.return_url || req.query.return_url || '';
  
  // Encode return_url in state parameter to preserve it through OAuth flow
  const state = returnUrl ? Buffer.from(JSON.stringify({ return_url: returnUrl })).toString('base64') : undefined;
  
  const authOptions = {
    scope: ['profile', 'email'],
    prompt: 'select_account',
    state: state
  };
  
  passport.authenticate('google', authOptions)(req, res, next);
});

app.get('/auth/google/callback',
  (req, res, next) => {
    // Store state in res.locals before passport regenerates the session
    if (req.query.state) {
      res.locals.oauthState = req.query.state;
    }
    next();
  },
  passport.authenticate('google', { 
    failureRedirect: '/login',
    failureFlash: 'Authentication failed. Please try again.'
  }),
  (req, res) => {
    // Restore return_url from state AFTER passport has regenerated the session
    if (res.locals.oauthState) {
      try {
        const stateData = JSON.parse(Buffer.from(res.locals.oauthState, 'base64').toString());
        if (stateData.return_url && isValidReturnUrl(stateData.return_url)) {
          req.session.return_url = stateData.return_url;
        }
      } catch (e) {
        console.warn('Failed to parse OAuth state:', e.message);
      }
    }
    
    // Save session before redirect
    req.session.save((err) => {
      if (err) console.error('Session save error:', err);
      res.redirect('/process-auth');
    });
  }
);

// Process authentication and set cookies
app.get('/process-auth', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }

  const email = req.user && req.user.email ? req.user.email : null;

  // Ensure the authenticated user has an email before proceeding
  if (!email) {
    const supportEmail = process.env.SUPPORT_EMAIL || '';
    const errorMsg = supportEmail
      ? `Your Google account does not provide an email address. Contact your administrator at ${supportEmail} for assistance.`
      : 'Your Google account does not provide an email address. Please contact your administrator for assistance.';
    req.flash('error', errorMsg);
    return res.render('unauthorized', {
      email: 'No email provided',
      returnUrl: req.session.return_url || '',
      supportEmail: supportEmail
    });
  }
  
  // Find user's subset
  const userSubset = getUserSubset(email, subsets);
  
  if (!userSubset) {
    const supportEmail = process.env.SUPPORT_EMAIL || '';
    const errorMsg = supportEmail 
      ? `This email is not authorized. Contact your administrator at ${supportEmail} for access.`
      : 'This email is not authorized. Please contact your administrator for access.';
    req.flash('error', errorMsg);
    return res.render('unauthorized', {
      email: email,
      returnUrl: req.session.return_url || '',
      supportEmail: supportEmail
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
  // Re-validate the stored return_url before redirecting to protect against session tampering
  const returnUrl = req.session.return_url;
  
  if (returnUrl && isValidReturnUrl(returnUrl)) {
    // Clear the stored return_url
    delete req.session.return_url;
    return res.redirect(returnUrl);
  }
  
  // If the stored return_url is present but invalid, clear it and fall through to success page
  if (returnUrl) {
    console.warn('Stored return_url failed re-validation, clearing:', returnUrl);
    delete req.session.return_url;
  }

  res.render('success', {
    user: req.user,
    subset: userSubset.name,
    cookiesSet: cookieConfigs.map(c => c.cookieName)
  });
});

// Try with different account
app.get('/try-different-account', (req, res) => {
  // Save return_url before logout (preserve it before any async operations)
  const savedReturnUrl = req.session.return_url;
  
  req.logout((err) => {
    if (err) {
      console.error('Logout error:', err);
      // Even on error, try to continue with the flow
    }
    
    // Restore return_url after successful logout
    if (savedReturnUrl) {
      req.session.return_url = savedReturnUrl;
    }
    
    // Save session before redirect to ensure return_url is persisted
    req.session.save((saveErr) => {
      if (saveErr) {
        console.error('Session save error:', saveErr);
      }
      // Redirect to Google OAuth with prompt for account selection
      res.redirect('/auth/google');
    });
  });
});

// Logout
app.get('/logout', (req, res) => {
  // Clear all JWT cookies with proper options
  const allCookieConfigs = getAllCookieConfigs();
  allCookieConfigs.forEach(config => {
    const clearOptions = {
      path: config.path || '/',
    };
    if (config.domain) {
      clearOptions.domain = config.domain;
    }
    res.clearCookie(config.cookieName, clearOptions);
  });

  // Only use session-stored return_url (already validated by storeReturnUrl middleware)
  // Do not accept unvalidated query parameters to prevent open redirect attacks
  const returnUrl = req.session.return_url;
  let logoutError = null;

  req.logout((logoutErr) => {
    if (logoutErr) {
      console.error('Logout error:', logoutErr);
      logoutError = logoutErr;
    }
    
    // Properly destroy session and wait for completion
    req.session.destroy((destroyErr) => {
      if (destroyErr) {
        console.error('Session destroy error:', destroyErr);
      }
      
      // If either operation failed, show error page with combined error info
      if (logoutError || destroyErr) {
        let errorMessages = [];
        if (logoutError && logoutError.message) {
          errorMessages.push(`Logout error: ${logoutError.message}`);
        }
        if (destroyErr && destroyErr.message) {
          errorMessages.push(`Session destroy error: ${destroyErr.message}`);
        }
        const combinedMessage = errorMessages.join(' | ') || 'Logout failed due to an unknown error.';
        return res.status(500).render('error', {
          message: 'Failed to complete logout. Please clear your cookies manually.',
          error: process.env.NODE_ENV === 'development' ? { message: combinedMessage } : {}
        });
      }
      
      if (returnUrl && isValidReturnUrl(returnUrl)) {
        return res.redirect(returnUrl);
      }
      res.redirect('/');
    });
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Cached cookie configurations for efficient logout (computed once at startup).
// This cache is built when first called and will not reflect runtime configuration changes.
// In production, environment variables should not change after the app starts.
let cachedCookieConfigs = null;

// Helper function to get all configured cookie names with their options (deduplicated)
function getAllCookieConfigs() {
  // Return cached result if available
  if (cachedCookieConfigs !== null) {
    return cachedCookieConfigs;
  }
  
  const cookieMap = new Map(); // Use Map to deduplicate by cookie name
  const cookieConfigPrefix = 'SUBSET_';
  const cookieConfigSuffix = '_COOKIES';
  
  Object.keys(process.env).forEach(key => {
    if (key.startsWith(cookieConfigPrefix) && key.endsWith(cookieConfigSuffix)) {
      const cookiesStr = process.env[key];
      if (cookiesStr) {
        cookiesStr.split(',').forEach(cookieName => {
          const name = cookieName.trim();
          // Only add if not already in the map (avoid duplicates)
          if (!cookieMap.has(name)) {
            const cookieEnvKey = name.replace(/-/g, '_');
            cookieMap.set(name, {
              cookieName: name,
              domain: process.env[`JWT_DOMAIN_${cookieEnvKey}`] || process.env.JWT_DEFAULT_DOMAIN,
              path: process.env[`JWT_PATH_${cookieEnvKey}`] || '/'
            });
          }
        });
      }
    }
  });
  
  // Cache the result for future calls
  cachedCookieConfigs = Array.from(cookieMap.values());
  return cachedCookieConfigs;
}

// Error handling
app.use((err, req, res, next) => {
  // Log error safely - log only message and stack in all environments
  // to avoid circular references or sensitive data in error objects
  console.error('Error:', err && err.message);
  if (err && err.stack) {
    console.error('Stack:', err.stack);
  }
  
  res.status(500).render('error', {
    message: 'An unexpected error occurred',
    error: process.env.NODE_ENV === 'development' ? { message: err.message, stack: err.stack } : {}
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
