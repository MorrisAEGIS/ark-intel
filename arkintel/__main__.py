from __future__ import annotations

import uvicorn

from .config import get_settings


if __name__ == "__main__":
    settings = get_settings()
    uvicorn.run("arkintel.main:app", host=settings.host, port=settings.port)
