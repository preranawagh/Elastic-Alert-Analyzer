"""
Fetch Elastic Security alerts, investigate each one, and write a
combined SOC report to disk.

Preferred automated entry point: pipeline.py (or run_pipeline.bat).
This module remains as a thin compatibility wrapper.
"""

from pipeline import main

if __name__ == "__main__":
    raise SystemExit(main())
