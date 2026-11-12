"""
Render-compatible startup script for MICHAEL – The Guardian AI.

Render injects a PORT environment variable but does NOT perform shell
expansion in its Start Command field, so passing --port $PORT fails.
This script reads PORT at Python runtime and calls uvicorn.run() directly.

Local development: defaults to port 8000 when PORT is not set.
Render production: uses whatever PORT Render injects (typically 10000).
"""
import os
import uvicorn

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=port,
        log_level="info",
    )

