const jwt = require('jsonwebtoken');
const config = require('./config');

const JWT_SECRET = config.JWT_SECRET;

/**
 * Helper to parse cookies from Request headers manually.
 */
function parseCookies(cookieHeader) {
  const list = {};
  if (!cookieHeader) return list;
  cookieHeader.split(';').forEach(cookie => {
    const parts = cookie.split('=');
    const name = parts.shift().trim();
    if (name) {
      list[name] = decodeURIComponent(parts.join('='));
    }
  });
  return list;
}

/**
 * Middleware to authenticate JWT tokens on protected routes.
 */
function authenticateToken(req, res, next) {
  // Bypassing static file paths and auth endpoints
  if (req.path.startsWith('/api/auth/')) {
    return next();
  }

  const cookies = parseCookies(req.headers.cookie);
  const tokenFromCookie = cookies.jwt_token;
  
  const authHeader = req.headers['authorization'];
  const tokenFromHeader = authHeader && authHeader.split(' ')[1];
  
  const token = tokenFromCookie || tokenFromHeader;

  if (!token) {
    return res.status(401).json({ success: false, message: 'Authentication required. Missing token.' });
  }

  // CSRF validation: If cookie is used, mutating endpoints must have X-Requested-With header
  if (tokenFromCookie && ['POST', 'PUT', 'DELETE'].includes(req.method)) {
    const csrfHeader = req.headers['x-requested-with'];
    if (!csrfHeader) {
      return res.status(403).json({
        success: false,
        message: 'CSRF validation failed. Missing X-Requested-With header.'
      });
    }
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid or expired token.' });
    }
    req.user = user;
    next();
  });
}

/**
 * Signs a JWT token with username and role.
 */
function generateToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });
}

/**
 * Middleware to authorize endpoints by user roles.
 */
function requireRole(roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Access Denied: Insufficient permissions for this action.'
      });
    }
    next();
  };
}

module.exports = {
  authenticateToken,
  generateToken,
  requireRole
};
