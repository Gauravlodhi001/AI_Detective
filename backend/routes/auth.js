const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const { z } = require('zod');
const { generateToken } = require('../utils/auth');
const logger = require('../utils/logger');

const config = require('../utils/config');

const USERS_FILE = path.join(__dirname, '../../reports/users.json');

// Ensure users file exists and seed default admin if empty
function initUsers() {
  let users = [];
  if (fs.existsSync(USERS_FILE)) {
    try {
      const data = fs.readFileSync(USERS_FILE, 'utf8');
      users = JSON.parse(data);
    } catch (e) {
      users = [];
    }
  }

  if (users.length === 0) {
    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(config.ADMIN_PASSWORD, salt);
    users.push({
      username: config.ADMIN_USERNAME,
      password: hashedPassword,
      role: 'admin',
      failedAttempts: 0,
      lockUntil: null
    });
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
    logger.info(`[AUDIT] Seeded default administrator account (username: ${config.ADMIN_USERNAME})`);
  }
}
initUsers();

// Zod schemas for validation
const authSchema = z.object({
  username: z.string().min(3).max(30).regex(/^[a-zA-Z0-9_]+$/, 'Username must be alphanumeric or underscores'),
  password: z.string().min(8).max(100)
});

function readUsers() {
  try {
    const data = fs.readFileSync(USERS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (e) {
    return [];
  }
}

function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
}

/**
 * @route POST /api/auth/register
 * @desc Register a new auditor user
 */
router.post('/register', async (req, res, next) => {
  try {
    const validationResult = authSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(400).json({
        success: false,
        message: (validationResult.error?.issues || validationResult.error?.errors || []).map(e => e.message).join(', ') || 'Validation failed'
      });
    }

    const { username, password } = validationResult.data;

    const users = readUsers();

    const existingUser = users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Username is already taken' });
    }

    // Password Hashing
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = {
      username,
      password: hashedPassword,
      role: 'auditor', // Only auditor role can be self-registered
      failedAttempts: 0,
      lockUntil: null
    };

    // Persistence
    users.push(newUser);
    writeUsers(users);

    logger.info(`[AUDIT] User registered successfully: ${username}`);

    const token = generateToken({ username: newUser.username, role: newUser.role });

    // Set secure cookie
    res.cookie('jwt_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 8 * 60 * 60 * 1000 // 8 hours
    });

    res.json({
      success: true,
      message: 'Registration successful',
      token,
      user: { username: newUser.username, role: newUser.role }
    });
  } catch (err) {
    next(err);
  }
});

/**
 * @route POST /api/auth/login
 * @desc Log in an existing user
 */
router.post('/login', async (req, res, next) => {
  try {
    const validationResult = authSchema.safeParse(req.body);
    if (!validationResult.success) {
      return res.status(400).json({
        success: false,
        message: (validationResult.error?.issues || validationResult.error?.errors || []).map(e => e.message).join(', ') || 'Validation failed'
      });
    }

    const { username, password } = validationResult.data;
    const users = readUsers();

    const userIndex = users.findIndex(u => u.username.toLowerCase() === username.toLowerCase());
    if (userIndex === -1) {
      logger.warn(`[AUDIT] Login failed: User not found: ${username}`);
      return res.status(401).json({ success: false, message: 'Invalid username or password' });
    }

    const user = users[userIndex];

    // Check account lockout status
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const remainingMin = Math.ceil((user.lockUntil - Date.now()) / (60 * 1000));
      logger.warn(`[AUDIT] Login rejected: Account locked out: ${username}`);
      return res.status(423).json({
        success: false,
        message: `Account is temporarily locked due to multiple failed login attempts. Try again in ${remainingMin} minute(s).`
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      // Increment failed login attempts
      user.failedAttempts = (user.failedAttempts || 0) + 1;
      if (user.failedAttempts >= 5) {
        user.lockUntil = Date.now() + 15 * 60 * 1000; // Lock for 15 minutes
        logger.warn(`[AUDIT] Account locked out due to failed logins: ${username}`);
      } else {
        logger.warn(`[AUDIT] Login failed: Invalid password for user: ${username} (Attempt ${user.failedAttempts}/5)`);
      }
      users[userIndex] = user;
      writeUsers(users);
      
      return res.status(401).json({ success: false, message: 'Invalid username or password' });
    }

    // Reset failed login attempts on successful login
    user.failedAttempts = 0;
    user.lockUntil = null;
    users[userIndex] = user;
    writeUsers(users);

    logger.info(`[AUDIT] User logged in: ${username}`);

    const token = generateToken({ username: user.username, role: user.role });

    // Set secure cookie
    res.cookie('jwt_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 8 * 60 * 60 * 1000 // 8 hours
    });

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: { username: user.username, role: user.role }
    });
  } catch (err) {
    next(err);
  }
});

/**
 * @route POST /api/auth/logout
 * @desc Clear authentication cookies
 */
router.post('/logout', (req, res) => {
  res.clearCookie('jwt_token');
  res.json({ success: true, message: 'Logged out successfully' });
});

module.exports = router;
