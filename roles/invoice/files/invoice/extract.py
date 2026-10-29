"""One PDF per process. The caller enforces the same deadline for both builds."""
import json
import sys
from PyPDF2 import PdfReader


def main():
    try:
        reader = PdfReader(sys.argv[1], strict=True)
        if len(reader.pages) > 20:
            raise ValueError("The invoice exceeds the page limit")
        text = "\n".join((page.extract_text() or "") for page in reader.pages)
        print(json.dumps({"status": "completed", "text": text[:20000]}))
    except Exception as error:
        print(json.dumps({"status": "rejected", "error_type": type(error).__name__}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
