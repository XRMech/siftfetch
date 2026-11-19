---
topic: MCP image evidence
status: verified
last-updated: 2026-11-18
---

# Read an image from a public page

Call `fetch_page_images` with a public page URL. The inventory lists up to
128 static HTTP(S) image sources with numbered labels, each limited to 256
characters. The inventory fetches only the page. Labels are page-authored
evidence inside SiftFetch's untrusted-content envelope.

To read an image, pass the same URL, its `image_number` (starting at 1),
the returned `inventory_token` as `expected_inventory`, and `operation` set
to `ocr` or `describe`. Each call obtains a fresh anonymous page. If the
final URL or listed image addresses, order or labels change, the tool returns
`inventory_changed` with the current inventory before downloading pixels.
A server restart requires a new inventory. Servers can change the image
bytes served by an unchanged address.

The reader accepts bounded PNG and JPEG images through the guarded public
transport. The local backend receives decoded pixels. OCR and descriptions
remain untrusted, with at most 30,000 backend text characters included.
Pages ineligible for capture return `call_only`.

Windows OCR uses the installed OCR language and the `windows-ocr` extra.
An operator can configure `SIFTFETCH_MCP_TESSERACT` with the absolute path
to a trusted, installed local Tesseract executable. For descriptions an
operator can call `siftfetch.mcp_images.configure_image_describer(callable)`
during trusted Python server startup. The callable receives one Pillow RGB
image and returns text. Choose a local backend and configure its resource
limits in the host. The MCP request contains only the page URL, operation
and selection. See [web image evidence](web-images.md).
