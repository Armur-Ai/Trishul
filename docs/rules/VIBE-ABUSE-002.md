# VIBE-ABUSE-002: File upload handler without a size limit

A file-upload handler is configured with no size limit.

## Metadata

| Field | Value |
| --- | --- |
| Severity | MEDIUM |
| Confidence | 0.50 |
| Maturity | stable |
| Mode | comment |
| Languages | javascript, typescript, python |
| File kinds | source |
| CWE | CWE-400 |
| OWASP | A04 |

## Description

A file-upload handler (multer/formidable/busboy/UploadFile/multipart) is configured in a
file that sets no upload size limit, so an attacker can exhaust disk/memory by uploading
arbitrarily large files.

## Fix

Configure an explicit upload size limit (multer `{ limits: { fileSize: N } }`, formidable `maxFileSize`, or a request body size limit).

## Examples

Bad:

```bad
const upload = multer({ dest: 'uploads/' })
```

Good:

```good
const upload = multer({ dest: 'uploads/', limits: { fileSize: 5 * 1024 * 1024 } })
```

