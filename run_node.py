import uvicorn
import logging
import os
from dotenv import dotenv_values

# Suppress uvicorn's default logging and warnings
# Configure uvicorn loggers to suppress WARNING messages
uvicorn_loggers = [
    logging.getLogger("uvicorn"),
    logging.getLogger("uvicorn.error"),
    logging.getLogger("uvicorn.access"),
    logging.getLogger("uvicorn.asgi"),
]

for uvicorn_logger in uvicorn_loggers:
    # Only show ERROR and CRITICAL, suppress WARNING
    uvicorn_logger.setLevel(logging.ERROR) 
    # Remove handlers to prevent duplicate output
    uvicorn_logger.handlers = []

config = dotenv_values(".env")

# Prioritize environment variables over .env file (for testnet configs)
QRDX_NODE_HOST = os.getenv("QRDX_NODE_HOST", config.get("QRDX_NODE_HOST", "127.0.0.1"))
QRDX_NODE_PORT = int(os.getenv("QRDX_NODE_PORT", config.get("QRDX_NODE_PORT", "3006")))

if __name__ == "__main__":
    uvicorn.run(
        "qrdx.node.main:app", 
        host=QRDX_NODE_HOST, 
        port=QRDX_NODE_PORT, 
        reload=False,
        access_log=False,
        log_config=None
    )

