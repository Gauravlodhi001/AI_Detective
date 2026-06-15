const { z } = require('zod');

const configSchema = z.object({
  PORT: z.coerce.number().default(3000),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  ALLOW_LOCAL_SCANS: z.string().default('false'),
  JWT_SECRET: z.string().min(16, 'JWT_SECRET must be at least 16 characters long').default('ai-detective-super-secret-key-12345-long-key-for-security'),
  CLAUDE_API_KEY: z.string().optional(),
  ADMIN_USERNAME: z.string().min(3).default('admin'),
  ADMIN_PASSWORD: z.string().min(8).default('admin12345'),
  REPORT_ENCRYPTION_KEY: z.string().length(64, 'REPORT_ENCRYPTION_KEY must be a 64-character hex string (32 bytes)').default('68656c6c6f20656e6372797074696f6e206b6579207365637265742031323334')
});

const parseResult = configSchema.safeParse({
  PORT: process.env.PORT,
  NODE_ENV: process.env.NODE_ENV,
  ALLOW_LOCAL_SCANS: process.env.ALLOW_LOCAL_SCANS,
  JWT_SECRET: process.env.JWT_SECRET,
  CLAUDE_API_KEY: process.env.CLAUDE_API_KEY,
  ADMIN_USERNAME: process.env.ADMIN_USERNAME,
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD,
  REPORT_ENCRYPTION_KEY: process.env.REPORT_ENCRYPTION_KEY
});

if (!parseResult.success) {
  console.error('Invalid configuration environment variables:');
  console.error(JSON.stringify(parseResult.error.format(), null, 2));
  process.exit(1);
}

const config = parseResult.data;

// Enforce that default configurations/secrets are NOT used in production
if (config.NODE_ENV === 'production') {
  if (config.ADMIN_PASSWORD === 'admin12345') {
    console.error('ERROR: Default ADMIN_PASSWORD cannot be used in production.');
    process.exit(1);
  }
  if (config.JWT_SECRET === 'ai-detective-super-secret-key-12345-long-key-for-security') {
    console.error('ERROR: Default JWT_SECRET cannot be used in production.');
    process.exit(1);
  }
  if (config.REPORT_ENCRYPTION_KEY === '68656c6c6f20656e6372797074696f6e206b6579207365637265742031323334') {
    console.error('ERROR: Default REPORT_ENCRYPTION_KEY cannot be used in production.');
    process.exit(1);
  }
}

if (config.NODE_ENV === 'development' && config.ALLOW_LOCAL_SCANS === 'true') {
  console.log('[CONFIG] SSRF Dev Scan Bypass is ENABLED.');
} else {
  console.log('[CONFIG] SSRF protection is ENABLED (Strict Mode).');
}

module.exports = config;
