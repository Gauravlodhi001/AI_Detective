const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const AdmZip = require('adm-zip');
const { z } = require('zod');
const { cloneRepo } = require('../utils/gitClone');
const { buildReport, buildMarkdownReport } = require('../parsers/report_builder');
const { generateAiAnalysis } = require('../utils/aiAnalyzer');
const { encrypt, decrypt } = require('../utils/crypto');

const pasteSchema = z.object({
  code: z.string().min(1, 'Code snippet is required'),
  filename: z.string().optional().default('snippet.js'),
  projectName: z.string().optional().default('Pasted Snippet')
});

const gitSchema = z.object({
  gitUrl: z.string().url('Invalid URL format').refine(val => val.startsWith('http://') || val.startsWith('https://'), {
    message: 'Only HTTP and HTTPS protocols are allowed'
  }),
  branch: z.string().optional()
});

// Configure multer for temporary zip storage
const upload = multer({
  dest: path.join(__dirname, '../../uploads'),
  limits: { fileSize: 1024 * 1024 * 50 } // Max 50MB zip files
});

/**
 * Utility to safely delete directories and files recursively.
 */
function safeCleanup(targetPath) {
  if (!targetPath || !fs.existsSync(targetPath)) return;
  try {
    fs.rmSync(targetPath, { recursive: true, force: true });
    console.log(`Successfully cleaned up path: ${targetPath}`);
  } catch (err) {
    console.error(`Failed to clean up path ${targetPath}:`, err);
  }
}

/**
 * @route POST /api/scan/paste
 * @desc Scan a single pasted code snippet
 */
router.post('/paste', async (req, res, next) => {
  const parseResult = pasteSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({
      success: false,
      message: (parseResult.error?.issues || parseResult.error?.errors || []).map(e => e.message).join(', ') || 'Validation failed'
    });
  }

  const { code, filename, projectName } = parseResult.data;

  // Extract basename to prevent path traversal
  const safeFilename = path.basename(filename);

  // Whitelist code/configuration extensions to prevent arbitrary writing
  const allowedExtensions = ['.js', '.jsx', '.ts', '.tsx', '.py', '.go', '.java', '.cpp', '.h', '.rb', '.php', '.cs', '.json', '.yml', '.yaml', '.md', '.txt', '.html', '.css'];
  const ext = path.extname(safeFilename).toLowerCase();

  if (!allowedExtensions.includes(ext)) {
    return res.status(400).json({ success: false, message: 'Invalid or forbidden file extension.' });
  }

  const timestamp = Date.now();
  const tempDir = path.join(__dirname, `../../uploads/paste-${timestamp}`);
  const tempFilePath = path.join(tempDir, safeFilename);

  try {
    // Write code to temporary file inside a dedicated directory
    fs.mkdirSync(tempDir, { recursive: true });
    fs.writeFileSync(tempFilePath, code, 'utf8');

    // Run scanner pipeline on the temp directory
    const report = await buildReport(tempDir, projectName);

    res.json({
      success: true,
      message: 'Scan completed successfully',
      report
    });
  } catch (err) {
    next(err);
  } finally {
    // Schedule folder deletion after response
    setTimeout(() => safeCleanup(tempDir), 2000);
  }
});

/**
 * @route POST /api/scan/upload
 * @desc Extract uploaded ZIP and scan it
 */
router.post('/upload', upload.single('zipFile'), async (req, res, next) => {
  if (!req.file) {
    return res.status(400).json({ success: false, message: 'Zip file upload is required' });
  }

  const zipPath = req.file.path;
  const timestamp = Date.now();
  const extractDir = path.join(__dirname, `../../uploads/extract-${timestamp}`);
  const projectName = req.body.projectName || req.file.originalname.replace(/\.zip$/i, '');

  // Validate file extension
  const fileExtension = path.extname(req.file.originalname).toLowerCase();
  if (fileExtension !== '.zip') {
    safeCleanup(zipPath);
    return res.status(400).json({ success: false, message: 'Only ZIP archives are allowed.' });
  }

  try {
    // Decompress zip file with security checks
    fs.mkdirSync(extractDir, { recursive: true });
    const zip = new AdmZip(zipPath);
    const zipEntries = zip.getEntries();

    // 1. Zip Bomb Protection: Max file count
    const MAX_FILE_COUNT = 10000;
    if (zipEntries.length > MAX_FILE_COUNT) {
      throw new Error(`ZIP archive contains too many files (max ${MAX_FILE_COUNT} allowed).`);
    }

    let totalDecompressedSize = 0;
    const MAX_TOTAL_SIZE = 1024 * 1024 * 200; // 200MB max total size
    const MAX_SINGLE_SIZE = 1024 * 1024 * 50; // 50MB max single file size

    // 2. Validate all entries first before writing anything
    for (const entry of zipEntries) {
      if (entry.isDirectory) continue;

      // Zip Bomb Check: File size
      const entrySize = entry.header.size;
      if (entrySize > MAX_SINGLE_SIZE) {
        throw new Error(`ZIP entry "${entry.entryName}" exceeds size limit of 50MB.`);
      }
      totalDecompressedSize += entrySize;
      if (totalDecompressedSize > MAX_TOTAL_SIZE) {
        throw new Error(`ZIP archive total decompressed size exceeds limit of 200MB.`);
      }

      // Zip Slip Protection: Path traversal check
      const entryName = entry.entryName;
      const targetFilePath = path.join(extractDir, entryName);

      const relative = path.relative(extractDir, targetFilePath);
      if (relative.startsWith('..') || path.isAbsolute(relative)) {
        throw new Error(`Directory traversal detected in ZIP entry: ${entryName}`);
      }
    }

    // 3. Extract safe entries
    for (const entry of zipEntries) {
      if (entry.isDirectory) continue;
      const entryName = entry.entryName;
      const targetFilePath = path.join(extractDir, entryName);
      const dir = path.dirname(targetFilePath);

      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(targetFilePath, entry.getData());
    }

    console.log(`Extracted zip safely to: ${extractDir}`);

    // Run scanner pipeline on the extracted folder
    const report = await buildReport(extractDir, projectName);

    res.json({
      success: true,
      message: 'Scan completed successfully',
      report
    });
  } catch (err) {
    next(err);
  } finally {
    // Clean up zip upload and extracted folder
    setTimeout(() => {
      safeCleanup(zipPath);
      safeCleanup(extractDir);
    }, 2000);
  }
});

/**
 * @route POST /api/scan/git
 * @desc Clone Git URL and scan it
 */
router.post('/git', async (req, res, next) => {
  const parseResult = gitSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({
      success: false,
      message: (parseResult.error?.issues || parseResult.error?.errors || []).map(e => e.message).join(', ') || 'Validation failed'
    });
  }

  const { gitUrl, branch } = parseResult.data;

  const timestamp = Date.now();
  const tempCloneDir = path.join(__dirname, `../../cloned_repos/git-${timestamp}`);

  try {
    console.log(`Git clone scan initiated. Target URL: ${gitUrl}`);
    const cloneResult = await cloneRepo(gitUrl, tempCloneDir);

    if (!cloneResult.success) {
      return res.status(500).json({
        success: false,
        message: cloneResult.error || 'Failed to clone the Git repository.'
      });
    }

    // Run scanner pipeline on cloned folder
    const report = await buildReport(tempCloneDir, cloneResult.repoName);

    res.json({
      success: true,
      message: 'Scan completed successfully',
      report
    });
  } catch (err) {
    next(err);
  } finally {
    // Clean up cloned folder
    setTimeout(() => safeCleanup(tempCloneDir), 2000);
  }
});

/**
 * @route POST /api/scan/:id/ai-analyze
 * @desc Generate AI threat assessment and attack narratives using Claude Sonnet
 */
router.post('/:id/ai-analyze', async (req, res, next) => {
  const reportId = path.basename(req.params.id);
  const reportsDir = path.join(__dirname, '../../reports');
  const jsonPath = path.join(reportsDir, `${reportId}.json`);

  if (!fs.existsSync(jsonPath)) {
    return res.status(404).json({ success: false, message: 'Report not found' });
  }

  try {
    const rawContent = fs.readFileSync(jsonPath, 'utf8');
    const reportData = JSON.parse(decrypt(rawContent));

    // Generate AI assessment (calls Claude API or triggers mock demo fallback)
    const aiAnalysis = await generateAiAnalysis(reportData);

    // Save to report
    reportData.aiAnalysis = aiAnalysis;
    fs.writeFileSync(jsonPath, encrypt(JSON.stringify(reportData)), 'utf8');

    // Rebuild Markdown report to include AI insights
    const mdPath = path.join(reportsDir, `${reportId}.md`);
    const markdownContent = buildMarkdownReport(reportData);
    fs.writeFileSync(mdPath, markdownContent, 'utf8');

    res.json({
      success: true,
      message: 'AI threat analysis completed successfully',
      aiAnalysis
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
