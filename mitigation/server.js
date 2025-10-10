app.post('/api/upload', upload.single('file'), (req, res) => {
  // Handle multipart/form-data uploads (browser)
  if (req.file) {
    const fileBuffer = fs.readFileSync(req.file.path);
    const headerBytes = fileBuffer.toString('utf8', 0, 20);

    // Basic content-type and signature check
    if (headerBytes.includes('<svg') || headerBytes.includes('<script')) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ success: false, error: 'Malicious SVG/script content detected and blocked.' });
    }

    return res.json({
      success: true,
      message: 'File uploaded successfully.',
      path: path.resolve(req.file.path),
      publicUrl: `/uploads/${req.file.filename}`
    });
  }

  // Handle JSON data-URL uploads
  if (req.is('application/json') && req.body && req.body.file) {
    const { file, name, mimeType } = req.body;
    const base64Data = file.split(',')[1];
    const decoded = Buffer.from(base64Data, 'base64').toString('utf8');

    // Detect malicious encoded scripts or SVGs
    const maliciousPatterns = /(<script|<svg|<iframe|onerror=|onload=|javascript:)/i;
    if (maliciousPatterns.test(decoded)) {
      return res.status(400).json({
        success: false,
        error: 'Malicious content detected after decoding. Upload rejected.'
      });
    }

    // Optional: verify actual image type from magic bytes
    const binaryBuffer = Buffer.from(base64Data, 'base64');
    const magic = binaryBuffer.toString('hex', 0, 4);
    const isJpeg = magic.startsWith('ffd8');
    const isPng = magic.startsWith('89504e47');
    const isHeic = magic.includes('66747970'); // generic check for HEIC

    if (!isJpeg && !isPng && !isHeic) {
      return res.status(400).json({
        success: false,
        error: 'File content does not match declared MIME type. Upload rejected.'
      });
    }

    // Save only after passing all checks
    const filename = name.replace(/[^a-zA-Z0-9_.-]/g, '_');
    const savePath = path.join(__dirname, 'uploads', filename);
    fs.writeFileSync(savePath, binaryBuffer);

    return res.json({
      success: true,
      message: 'File uploaded securely after validation.',
      path: path.resolve(savePath),
      publicUrl: `/uploads/${filename}`
    });
  }

  return res.status(400).json({ success: false, error: 'Invalid upload request.' });
});
