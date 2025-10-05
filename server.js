// server.js
// Demo server: single /api/upload endpoint handles both multipart file uploads and JSON data-url uploads.
// Intentionally vulnerable to the base64 + mimeType trust bypass described in the lab.

const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const mime = require('mime-types');

const app = express();
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

// Multer setup for multipart/form-data uploads (regular browser upload)
const storage = multer.memoryStorage(); // we will inspect buffer
const upload = multer({ storage });

// allow JSON bodies (for data URL uploads)
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve front-end
app.use('/', express.static(path.join(__dirname, 'public')));

// Helper: detect SVG by checking for "<svg" or "<?xml"
function looksLikeSvg(buffer) {
  if (!buffer) return false;
  const head = buffer.slice(0, 4096).toString('utf8').toLowerCase();
  return head.includes('<svg') || head.includes('<?xml') && head.includes('svg');
}

// Allowed mimetypes we claim to accept
const ALLOWED_MIMES = ['image/jpg', 'image/jpeg', 'image/png', 'image/heic'];

// Single upload endpoint: handles either multipart/form-data (regular browser) or JSON payload {file: "data:...base64...", name:"x.jpg", mimeType:"image/jpeg"}
app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    // Path: multipart/form-data (browser file input)
    if (req.is('multipart/form-data')) {
      if (!req.file) return res.status(400).json({ success: false, error: 'No file field' });

      const buf = req.file.buffer;
      const originalName = req.file.originalname || 'upload.dat';
      const ext = path.extname(originalName).toLowerCase();

      // Strong server-side check for SVG for the "normal upload" path: block if actual content looks like SVG
      if (looksLikeSvg(buf) || ext === '.svg') {
        console.log(`[BLOCKED] Multipart upload blocked: detected SVG content — ${originalName}`);
        return res.status(400).json({ success: false, error: 'SVG files are not allowed (server blocked).' });
      }

      // save file as-is (use original filename)
      const outPath = path.join(UPLOAD_DIR, originalName);
      fs.writeFileSync(outPath, buf);
      const publicUrl = `/uploads/${encodeURIComponent(originalName)}`;
      console.log(`[SAVED] multipart -> ${outPath}`);
      return res.json({ success: true, message: 'Uploaded (multipart)', path: outPath, publicUrl });
    }

    // Path: JSON data URL (attacker supplies "file": "data:...;base64,....", "name": "xss.jpg", "mimeType": "image/jpeg")
    // THIS PATH IS INTENTIONALLY VULNERABLE: trusts client-sent mimeType and name without strong content checks.
    if (req.is('application/json') || req.body && req.body.file) {
      const { file: dataUrl, name, mimeType } = req.body;

      if (!dataUrl || !name || !mimeType) {
        return res.status(400).json({ success: false, error: 'Missing file, name, or mimeType in JSON body.' });
      }

      // parse data URL
      const m = dataUrl.match(/^data:(.+?);base64,(.+)$/);
      if (!m) return res.status(400).json({ success: false, error: 'file must be a data URL (data:*;base64,...)' });

      const declaredMime = (mimeType || m[1] || '').toLowerCase();
      const base64 = m[2];
      const buf = Buffer.from(base64, 'base64');

      // Vulnerable behavior:
      // - Instead of validating file contents, we *trust* the client-provided mimeType (declaredMime)
      // - We allow upload if declaredMime is within ALLOWED_MIMES.
      if (!ALLOWED_MIMES.includes(declaredMime)) {
        return res.status(400).json({ success: false, error: 'Declared mimeType not allowed by server policy.' });
      }

      // Save file using the provided name (no sanitization) -- intentionally vulnerable.
      const outPath = path.join(UPLOAD_DIR, path.basename(name));
      fs.writeFileSync(outPath, buf);

      // Log the saved path on backend
      console.log(`[SAVED - VULNERABLE PATH] ${outPath} (declared mime: ${declaredMime})`);

      // Return public URL and file path
      const publicUrl = `/uploads/${encodeURIComponent(path.basename(name))}`;
      return res.json({
        success: true,
        message: 'Uploaded (JSON/data-url) — server trusted declared mimeType',
        path: outPath,
        publicUrl
      });
    }

    // If we get here, we didn't detect a valid path
    res.status(400).json({ success: false, error: 'Unsupported content type or missing file.' });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Vulnerable file serving route.
// This intentionally content-sniffs files and sets Content-Type based on content if it looks like SVG,
// which reproduces the lab behavior where disguised SVG content executes when visiting the URL.
app.get('/uploads/:name', (req, res) => {
  const fileName = path.basename(req.params.name); // sanitize minimal
  const full = path.join(UPLOAD_DIR, fileName);
  if (!fs.existsSync(full)) return res.status(404).send('Not found');

  const buf = fs.readFileSync(full);

  // If file content looks like SVG, send it as image/svg+xml (vulnerable content sniffing)
  if (looksLikeSvg(buf)) {
    res.setHeader('Content-Type', 'image/svg+xml'); // Vulnerable: serving based on content sniffing
    return res.send(buf);
  }

  // Otherwise use mime-types based on extension
  const type = mime.lookup(fileName) || 'application/octet-stream';
  res.setHeader('Content-Type', type);
  res.send(buf);
});

// Simple static route to get the upload page (public folder)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Demo running on http://localhost:${PORT}`));
