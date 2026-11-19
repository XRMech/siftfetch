"""Measure offline HTML extraction with production cleaning and envelope rendering."""
import argparse
from hashlib import sha256
from pathlib import Path
import re

from siftfetch.cleaner import clean_html
from siftfetch.injection_scan import _envelope
from siftfetch.tools import _label_content


CORPUS = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "extraction"
VIEWS = ("auto", "readability", "full", "raw")
EVIDENCE = {
    "stations": ("| Station | Rainfall | Coverage |", "| Alder Creek | 10 mm | 24 days |",
                 "| Willow Creek | 32 mm | 13 days |"),
    "article": ("37 nesting pairs on North Island", "covers the north shore only"),
    "table": ("| Landing | Departure | Dock |", "| East Pier | 07:15 | B |",
              "| West Pier | 08:40 | A |"),
    "reference": ("reference reads 12 millimetres", "after six sampling cycles"),
}


def _responses():
    for page, evidence in EVIDENCE.items():
        html = (CORPUS / f"{page}.html").read_text(encoding="utf-8")
        url = f"https://benchmark.example/{page}"
        for view in VIEWS:
            cleaned = clean_html(html, url=url, extract=view)
            labeled, scan = _label_content(cleaned, html)
            response = _envelope(labeled, url, scan)
            missing = [span for span in evidence if span not in response]
            yield page, view, html, response, cleaned.truncated, missing


def measure():
    for page, view, html, response, truncated, missing in _responses():
        yield page, view, len(html.encode()), len(response.encode()), truncated, missing


def _fixed_timestamps(response):
    # Digit groupings change token counts. Normalize the generated metadata
    # fields only. Their fixed-width values have no effect on the byte report.
    response = re.sub(r"(?m)^(source=\S+ fetched=)\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ",
                      r"\g<1>2000-01-01T00:00:00Z", response, count=1)
    return re.sub(r"(?m)^\*Fetched: \d{4}-\d\d-\d\d\*$", "*Fetched: 2000-01-01*",
                  response, count=1)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tokenizer", metavar="NAME", help="identifier of the local tokenizer")
    parser.add_argument("--tokenizer-file", type=Path, metavar="PATH", help="local tokenizer.json")
    args = parser.parse_args(argv)
    if bool(args.tokenizer) != bool(args.tokenizer_file):
        parser.error("--tokenizer and --tokenizer-file must be supplied together")
    tokenizer = None
    header = "page       view         HTML bytes  response bytes    saved"
    if args.tokenizer_file:
        try:
            import tokenizers
        except ImportError:
            parser.error("optional dependency tokenizers is required for token measurements")
        try:
            data = args.tokenizer_file.read_bytes()
            tokenizer = tokenizers.Tokenizer.from_buffer(data)
        except Exception as exc:
            parser.error(f"cannot load local tokenizer: {exc}")
        tokenizer.no_truncation()
        tokenizer.no_padding()
        print(f"Tokenizer {args.tokenizer} | tokenizers {tokenizers.__version__}"
              f" | tokenizer.json SHA-256 {sha256(data).hexdigest()}")
        header += "  HTML tokens  response tokens    saved"
    print(header + "  truncated  evidence")
    failed = False
    for page, view, html, response, truncated, missing in _responses():
        source, result = len(html.encode()), len(response.encode())
        row = f"{page:10} {view:12} {source:10} {result:15} {1-result/source:8.1%}"
        if tokenizer is not None:
            source_tokens = len(tokenizer.encode(html, add_special_tokens=False).ids)
            rendered = _fixed_timestamps(response)
            result_tokens = len(tokenizer.encode(rendered, add_special_tokens=False).ids)
            savings = f"{1 - result_tokens / source_tokens:8.1%}" if source_tokens else "     n/a"
            row += f"  {source_tokens:11} {result_tokens:15} {savings}"
        status = "missing " + repr(missing) if missing else "pass"
        print(f"{row}  {str(truncated):9}  {status}")
        failed |= bool(missing)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
