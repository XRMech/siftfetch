---
topic: web-images
status: verified
last-updated: 2026-11-18
---

# Image evidence from a public page

Use an eligible [Python snapshot](library-api.md#public-html-snapshots). The inventory parses static HTML locally and returns capture-scoped IDs and an enveloped list with page-supplied alt text. Listing costs zero image requests. It covers the first 128 supported HTTP(S) `img src` entries and honors the first HTML base URL. The inventory's `truncated` field reports additional entries or alt text clipped at 256 characters. The returned grade includes the risk observed on the captured page. Dynamic images, CSS backgrounds and responsive source selection are outside this inventory.

```python
from siftfetch.research_flow import ResearchFlow
from siftfetch.web_images import image_inventory, read_image

with ResearchFlow() as flow:
    page = flow.fetch("https://example.com/")
    if page.handle:
        images = image_inventory(flow, page.handle)
        if images.ids:
            evidence = read_image(flow, page.handle, images.ids[0],
                                  tesseract="/usr/bin/tesseract")
```

Install the optional `images` extra for selected-image reads. On Windows, install the `windows-ocr` extra and pass `windows_ocr=True` to use the installed offline recognition language. Call from a worker thread in an asynchronous host. For Tesseract OCR, supply the absolute path to a trusted, installed Tesseract executable. The example path is platform-specific. For a locally computed description, supply `describe=callable` instead. The host chooses and enforces a local backend. The callable receives a decoded RGB image and returns text. Supply executable paths and backend configuration from trusted host settings. Keep them out of page-controlled inputs.

Each selected read retrieves that image at read time with anonymous, policy-checked requests. Every redirect uses the same checks and only public destinations are eligible. Limits are 30 seconds for retrieval, 4 MiB of decoded transfer data, 8 million pixels, and one frame of PNG or JPEG. Processing applies image orientation, composites transparency on white and removes metadata. The inventory refers to the captured page; the image at its URL can change. Text returned to the caller is marked as OCR or an untrusted generated interpretation, includes the page, image ID and final image provenance with query and fragment removed, and is capped at 30,000 characters before labeling. The browser, default page reads and inventory can operate without an image backend.
