# STORED-XSS-SIMULATION
This project demonstrates a Stored XSS vulnerability through file upload bypass using an insecure file validation mechanism. The web application is intentionally designed for research and educational use to support an IEEE paper on Stored XSS. The main objective is to show how attackers can upload a malicious `.svg` file disguised as an allowed image type like `.jpg` and trigger JavaScript execution when the uploaded file is rendered.

The application uses a single API endpoint `/api/upload` to handle all uploads. Normal browser-based multipart uploads strictly allow only `.jpg`, `.jpeg`, `.png`, and `.heic` formats. Attempts to upload `.svg` files are blocked on the server side. However, the same API also accepts JSON requests where users can provide base64-encoded file data, along with fields like `name`, `mimeType`, and `file`. The vulnerability exists because the server trusts these client-supplied values without verifying the actual file content. This allows an attacker to send an `.svg` payload disguised as a `.jpg` file by modifying the `mimeType` and `file` parameters in the JSON body.

To set up the environment, first install Node.js (v14 or higher) and open the project in VS Code. Run `npm install` to install dependencies, followed by `npm start` to launch the application. Once started, open the browser at `http://localhost:3000`. The UI displays a single, fixed, and centered file upload section where users can select an image and upload it. When an image is uploaded successfully, the page displays the upload status, server path, and public URL of the uploaded file. All files are stored in the `/uploads` directory, which the server automatically creates at runtime.

To test the normal upload functionality, create a simple SVG payload named `xss.svg`. You can upload it via the browser or with the following command:

```
curl -v -F "file=@xss.svg" http://localhost:3000/api/upload
```

The server will detect the SVG content and block it, returning a JSON response such as:

```
{"success": false, "error": "SVG files are not allowed (server blocked)."}
```

This confirms that the server’s normal upload validation works correctly.

To demonstrate the bypass, rename the file and encode it in base64 format. Use the following commands:

```
mv xss.svg xss.jpg
base64 xss.jpg > xss.b64
```

Now send a JSON request to the same upload endpoint, where the actual content is an SVG, but the declared `mimeType` and filename pretend to be JPEG:

```
BASE64=$(cat xss.b64)
curl -v -H "Content-Type: application/json" \
-d "{\"file\":\"data:image/svg+xml;base64,${BASE64}\",\"name\":\"xss.jpg\",\"mimeType\":\"image/jpeg\"}" \
http://localhost:3000/api/upload
```

The server trusts the declared type and accepts the upload. The response confirms the upload and returns both the file’s server path and its public URL:

```
{"success": true, "message": "Uploaded (JSON/data-url) — server trusted declared mimeType","path":"/uploads/xss.jpg","publicUrl":"/uploads/xss.jpg"}
```

When you visit the given public URL in your browser, the stored SVG executes the embedded JavaScript, triggering an alert box with the message `Stored XSS executed!`. This proves the successful bypass of the upload restriction through manipulated JSON parameters.

This lab environment provides a clear demonstration of how improper file validation and trusting client-provided MIME types can lead to Stored Cross-Site Scripting vulnerabilities. To prevent such vulnerabilities, developers should verify actual file content based on magic bytes, sanitize or disallow SVG uploads, store user files with randomized names, and enforce strict `Content-Type` handling with headers like `X-Content-Type-Options: nosniff`. Additionally, separating file uploads to a non-executable domain or subdomain can further mitigate the risk.
