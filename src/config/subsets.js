/**
 * Subset Configuration Parser
 * 
 * This module parses subset and cookie configurations from environment variables.
 * 
 * Environment variable format:
 * 
 * SUBSETS=A,B,C                              # List of subset names
 * SUBSET_A_EMAILS=user1@example.com,user2@example.com
 * SUBSET_B_EMAILS=user3@example.com
 * 
 * SUBSET_A_COOKIES=auth-token                # Cookie names for subset A
 * SUBSET_B_COOKIES=auth-token,admin-token    # Cookie names for subset B
 * 
 * JWT_SECRET_auth-token=your-secret-key      # Secret for auth-token cookie
 * JWT_ALGORITHM_auth-token=HS256             # Algorithm for auth-token (optional, default HS256)
 * JWT_EXPIRES_auth-token=24h                 # Expiration for auth-token (optional, default 24h)
 * JWT_DOMAIN_auth-token=.example.com         # Cookie domain (optional)
 * JWT_PATH_auth-token=/                      # Cookie path (optional, default /)
 * JWT_HTTPONLY_auth-token=true               # HttpOnly flag (optional, default true)
 * JWT_MAXAGE_auth-token=86400000             # Max age in milliseconds (optional)
 * JWT_SAMESITE_auth-token=lax                # SameSite attribute (optional, default lax)
 * JWT_CLAIMS_auth-token=role:user,type:api   # Additional claims (optional, key:value pairs)
 */

/**
 * Parse all subsets from environment variables
 * @returns {Object} Object with subset names as keys and email arrays as values
 */
function parseSubsets() {
  const subsets = {};
  
  // Get list of subset names
  const subsetNames = process.env.SUBSETS ? process.env.SUBSETS.split(',').map(s => s.trim()) : [];
  
  subsetNames.forEach(name => {
    const emailsKey = `SUBSET_${name}_EMAILS`;
    const emails = process.env[emailsKey] ? process.env[emailsKey].split(',').map(e => e.trim().toLowerCase()) : [];
    
    if (emails.length > 0) {
      subsets[name] = {
        name: name,
        emails: emails
      };
    }
  });
  
  return subsets;
}

/**
 * Find which subset a user's email belongs to
 * @param {string} email - User's email address
 * @param {Object} subsets - Parsed subsets object
 * @returns {Object|null} Subset object or null if not found
 */
function getUserSubset(email, subsets) {
  const normalizedEmail = email.toLowerCase();
  
  for (const subset of Object.values(subsets)) {
    if (subset.emails.includes(normalizedEmail)) {
      return subset;
    }
  }
  
  return null;
}

/**
 * Parse additional claims from environment variable
 * @param {string} claimsStr - Claims string in format "key1:value1,key2:value2"
 * @returns {Object} Object with claim key-value pairs
 */
function parseAdditionalClaims(claimsStr) {
  const claims = {};
  
  if (!claimsStr) return claims;
  
  claimsStr.split(',').forEach(pair => {
    const [key, value] = pair.split(':').map(s => s.trim());
    if (key && value !== undefined) {
      // Try to parse as number or boolean
      if (value === 'true') {
        claims[key] = true;
      } else if (value === 'false') {
        claims[key] = false;
      } else {
        const trimmedValue = value.trim();
        if (trimmedValue !== '' && !isNaN(Number(trimmedValue))) {
          claims[key] = Number(trimmedValue);
        } else {
          claims[key] = value;
        }
      }
    }
  });
  
  return claims;
}

// Supported JWT algorithms
const SUPPORTED_ALGORITHMS = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'];

/**
 * Parse boolean from environment variable with robust handling
 * @param {string} value - The environment variable value
 * @param {boolean} defaultValue - Default value if not set
 * @returns {boolean} Parsed boolean value
 */
function parseBoolean(value, defaultValue = true) {
  if (value === undefined || value === null || value === '') {
    return defaultValue;
  }
  const normalizedValue = String(value).toLowerCase().trim();
  const falsyValues = ['false', '0', 'no', 'off', 'disabled'];
  return !falsyValues.includes(normalizedValue);
}

/**
 * Get cookie configuration for a specific subset
 * @param {string} subsetName - Name of the subset
 * @returns {Array} Array of cookie configuration objects
 */
function getCookieConfigForSubset(subsetName) {
  const cookiesKey = `SUBSET_${subsetName}_COOKIES`;
  const cookieNames = process.env[cookiesKey] ? process.env[cookiesKey].split(',').map(c => c.trim()) : [];
  
  // If no specific cookies configured, use default
  if (cookieNames.length === 0) {
    cookieNames.push('auth-token');
  }
  
  // Valid expiresIn format patterns (e.g., '24h', '7d', '30m', '3600', '1y')
  const validExpiresInPattern = /^(\d+)(s|m|h|d|w|y)?$/i;
  
  return cookieNames.map(cookieName => {
    // Replace hyphens with underscores for env var lookup to match our JWT_* naming convention
    const cookieEnvKey = cookieName.replace(/-/g, '_');
    
    const secret = process.env[`JWT_SECRET_${cookieEnvKey}`] || process.env.JWT_DEFAULT_SECRET;
    if (!secret) {
      throw new Error(`JWT secret not configured for cookie "${cookieName}". Set JWT_SECRET_${cookieEnvKey} or JWT_DEFAULT_SECRET environment variable.`);
    }
    
    // Validate algorithm
    const algorithm = process.env[`JWT_ALGORITHM_${cookieEnvKey}`] || process.env.JWT_DEFAULT_ALGORITHM || 'HS256';
    if (!SUPPORTED_ALGORITHMS.includes(algorithm)) {
      throw new Error(`Invalid JWT algorithm "${algorithm}" for cookie "${cookieName}". Supported algorithms: ${SUPPORTED_ALGORITHMS.join(', ')}`);
    }
    
    // Validate expiresIn format
    const expiresIn = process.env[`JWT_EXPIRES_${cookieEnvKey}`] || process.env.JWT_DEFAULT_EXPIRES || '24h';
    if (!validExpiresInPattern.test(expiresIn)) {
      throw new Error(`Invalid JWT expiresIn format "${expiresIn}" for cookie "${cookieName}". Use formats like '24h', '7d', '30m', '3600', or '1y'.`);
    }
    
    return {
      cookieName: cookieName,
      secret: secret,
      algorithm: algorithm,
      expiresIn: expiresIn,
      domain: process.env[`JWT_DOMAIN_${cookieEnvKey}`] || process.env.JWT_DEFAULT_DOMAIN,
      path: process.env[`JWT_PATH_${cookieEnvKey}`] || '/',
      httpOnly: parseBoolean(process.env[`JWT_HTTPONLY_${cookieEnvKey}`], true),
      maxAge: process.env[`JWT_MAXAGE_${cookieEnvKey}`] ? parseInt(process.env[`JWT_MAXAGE_${cookieEnvKey}`], 10) : 24 * 60 * 60 * 1000,
      sameSite: process.env[`JWT_SAMESITE_${cookieEnvKey}`] || 'lax',
      additionalClaims: parseAdditionalClaims(process.env[`JWT_CLAIMS_${cookieEnvKey}`])
    };
  });
}

/**
 * Validate the environment-based subset and authentication configuration.
 *
 * This function inspects the current process.env values used by subset parsing
 * and cookie/JWT configuration (such as GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET,
 * SUBSETS, per-subset email/cookie variables, and SESSION_SECRET). It performs
 * a best-effort validation to detect missing values and common placeholder
 * patterns that should not be used in production.
 *
 * It is intended to be called during application start-up, before handling
 * any requests, so that configuration problems can be surfaced early.
 * The function does not throw; instead it returns a summary object that
 * callers can use to decide whether to continue starting the application
 * (for example by logging warnings) or to abort start-up when fatal errors
 * are present.
 *
 * @returns {{isValid: boolean, errors: string[], warnings: string[]}}
 *          An object containing:
 *          - `isValid`: `true` if no fatal errors were found, `false` otherwise.
 *          - `errors`: a list of fatal configuration issues that must be fixed.
 *          - `warnings`: a list of non-fatal issues that should be reviewed.
 */
function validateConfiguration() {
  const errors = [];
  const warnings = [];
  const isProduction = process.env.NODE_ENV === 'production';
  
  // Placeholder values that should not be used in production
  const placeholderPatterns = [
    /^your-/i,
    /^example-/i,
    /^placeholder/i,
    /^change-me/i,
    /^test-/i
  ];
  
  const isPlaceholder = (value) => {
    if (!value) return false;
    return placeholderPatterns.some(pattern => pattern.test(value.trim()));
  };
  
  // Check for required environment variables
  const googleClientId = process.env.GOOGLE_CLIENT_ID ? process.env.GOOGLE_CLIENT_ID.trim() : '';
  const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET ? process.env.GOOGLE_CLIENT_SECRET.trim() : '';
  
  if (!googleClientId) {
    errors.push('GOOGLE_CLIENT_ID is required');
  } else if (isPlaceholder(googleClientId)) {
    errors.push('GOOGLE_CLIENT_ID is set to a placeholder value and must be replaced with a valid client ID');
  }
  
  if (!googleClientSecret) {
    errors.push('GOOGLE_CLIENT_SECRET is required');
  } else if (isPlaceholder(googleClientSecret)) {
    errors.push('GOOGLE_CLIENT_SECRET is set to a placeholder value and must be replaced with a valid client secret');
  }
  
  // Check for subsets
  if (!process.env.SUBSETS) {
    warnings.push('SUBSETS is not configured. No users will be authorized.');
  } else {
    const subsetNames = process.env.SUBSETS.split(',').map(s => s.trim());
    
    subsetNames.forEach(name => {
      const emailsKey = `SUBSET_${name}_EMAILS`;
      if (!process.env[emailsKey]) {
        warnings.push(`${emailsKey} is not configured for subset ${name}`);
      }
      
      const cookiesKey = `SUBSET_${name}_COOKIES`;
      if (process.env[cookiesKey]) {
        const cookies = process.env[cookiesKey].split(',').map(c => c.trim());
        cookies.forEach(cookie => {
          const cookieEnvKey = cookie.replace(/-/g, '_');
          const secretKey = `JWT_SECRET_${cookieEnvKey}`;
          if (!process.env[secretKey] && !process.env.JWT_DEFAULT_SECRET) {
            warnings.push(`${secretKey} is not configured and no JWT_DEFAULT_SECRET provided`);
          }
        });
      }
    });
  }
  
  // Check session secret - more strict in production
  const sessionSecret = process.env.SESSION_SECRET ? process.env.SESSION_SECRET.trim() : '';
  if (!sessionSecret) {
    if (isProduction) {
      errors.push('SESSION_SECRET is required in production. Please set a strong, random SESSION_SECRET.');
    } else {
      warnings.push('SESSION_SECRET is not configured.');
    }
  } else if (isPlaceholder(sessionSecret)) {
    if (isProduction) {
      errors.push('SESSION_SECRET is set to a placeholder value. Placeholder secrets are not allowed in production.');
    } else {
      warnings.push('SESSION_SECRET appears to be a placeholder value. Please use a secure random secret.');
    }
  }
  
  return {
    isValid: errors.length === 0,
    errors,
    warnings
  };
}

module.exports = {
  parseSubsets,
  getUserSubset,
  getCookieConfigForSubset,
  validateConfiguration,
  parseAdditionalClaims
};
