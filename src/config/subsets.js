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
  
  for (const [name, subset] of Object.entries(subsets)) {
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
      } else if (value.trim() !== '' && !isNaN(Number(value))) {
        claims[key] = Number(value);
      } else {
        claims[key] = value;
      }
    }
  });
  
  return claims;
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
  
  return cookieNames.map(cookieName => {
    // Replace hyphens with underscores for env var lookup since env vars can't have hyphens
    const envCookieName = cookieName.replace(/-/g, '_');
    
    const secret = process.env[`JWT_SECRET_${envCookieName}`] || process.env.JWT_DEFAULT_SECRET;
    if (!secret) {
      throw new Error(`JWT secret not configured for cookie "${cookieName}". Set JWT_SECRET_${envCookieName} or JWT_DEFAULT_SECRET environment variable.`);
    }
    
    return {
      cookieName: cookieName,
      secret: secret,
      algorithm: process.env[`JWT_ALGORITHM_${envCookieName}`] || process.env.JWT_DEFAULT_ALGORITHM || 'HS256',
      expiresIn: process.env[`JWT_EXPIRES_${envCookieName}`] || process.env.JWT_DEFAULT_EXPIRES || '24h',
      domain: process.env[`JWT_DOMAIN_${envCookieName}`] || process.env.JWT_DEFAULT_DOMAIN,
      path: process.env[`JWT_PATH_${envCookieName}`] || '/',
      httpOnly: process.env[`JWT_HTTPONLY_${envCookieName}`] !== 'false',
      maxAge: process.env[`JWT_MAXAGE_${envCookieName}`] ? parseInt(process.env[`JWT_MAXAGE_${envCookieName}`], 10) : 24 * 60 * 60 * 1000,
      sameSite: process.env[`JWT_SAMESITE_${envCookieName}`] || 'lax',
      additionalClaims: parseAdditionalClaims(process.env[`JWT_CLAIMS_${envCookieName}`])
    };
  });
}

/**
 * Validate the subset configuration
 * @returns {Object} Validation result with isValid and errors array
 */
function validateConfiguration() {
  const errors = [];
  const warnings = [];
  
  // Check for required environment variables
  if (!process.env.GOOGLE_CLIENT_ID) {
    errors.push('GOOGLE_CLIENT_ID is required');
  }
  if (!process.env.GOOGLE_CLIENT_SECRET) {
    errors.push('GOOGLE_CLIENT_SECRET is required');
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
          const envCookieName = cookie.replace(/-/g, '_');
          const secretKey = `JWT_SECRET_${envCookieName}`;
          if (!process.env[secretKey] && !process.env.JWT_DEFAULT_SECRET) {
            warnings.push(`${secretKey} is not configured and no JWT_DEFAULT_SECRET provided`);
          }
        });
      }
    });
  }
  
  // Check session secret
  if (!process.env.SESSION_SECRET) {
    warnings.push('SESSION_SECRET is not configured. Using default value.');
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
