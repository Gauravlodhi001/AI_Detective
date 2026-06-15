const crypto = require('crypto');
const config = require('./config');

const GCM_ALGORITHM = 'aes-256-gcm';
const CBC_ALGORITHM = 'aes-256-cbc';

// Load the 32-byte encryption key from config hex string
const ENCRYPTION_KEY = Buffer.from(config.REPORT_ENCRYPTION_KEY, 'hex');

// Legacy key derived from JWT_SECRET for backward-compatibility CBC fallback
const LEGACY_SECRET_KEY = crypto.createHash('sha256').update(config.JWT_SECRET).digest();

/**
 * Encrypts a cleartext string using AES-256-GCM.
 * Output format: iv_hex:auth_tag_hex:ciphertext_hex
 */
function encrypt(text) {
  if (!text) return '';
  const iv = crypto.randomBytes(12); // Standard 12-byte IV for GCM
  const cipher = crypto.createCipheriv(GCM_ALGORITHM, ENCRYPTION_KEY, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag().toString('hex');
  
  return iv.toString('hex') + ':' + authTag + ':' + encrypted;
}

/**
 * Decrypts an encrypted string payload, supporting both GCM and legacy CBC formats.
 */
function decrypt(text) {
  if (!text) return '';
  try {
    const parts = text.split(':');
    
    // Case 1: Legacy CBC Format (iv:ciphertext)
    if (parts.length === 2) {
      const iv = Buffer.from(parts[0], 'hex');
      const encryptedText = Buffer.from(parts[1], 'hex');
      
      const decipher = crypto.createDecipheriv(CBC_ALGORITHM, LEGACY_SECRET_KEY, iv);
      let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    }
    
    // Case 2: Upgraded GCM Format (iv:authTag:ciphertext)
    if (parts.length === 3) {
      const iv = Buffer.from(parts[0], 'hex');
      const authTag = Buffer.from(parts[1], 'hex');
      const encryptedText = Buffer.from(parts[2], 'hex');
      
      const decipher = crypto.createDecipheriv(GCM_ALGORITHM, ENCRYPTION_KEY, iv);
      decipher.setAuthTag(authTag);
      
      let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    }
    
    // Fallback for old unencrypted reports
    return text;
  } catch (err) {
    // If decryption fails, return original string (allows migration/graceful recovery)
    return text;
  }
}

module.exports = {
  encrypt,
  decrypt
};
