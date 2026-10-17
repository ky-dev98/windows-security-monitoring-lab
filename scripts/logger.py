from mitmproxy import http
import json
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
import logging

LOG_FILE = r"<PROJECT_PATH>\log_monitor_lab\logs\mitmproxy.jsonl"

logger = logging.getLogger("mitmproxy_json")
logger.setLevel(logging.INFO)

handler = RotatingFileHandler(
    LOG_FILE,
    maxBytes=100 * 1024 * 1024,  # 100 MB
    backupCount=4,               # Keep the current log file and 4 backup files
    encoding="utf-8"
)

handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(handler)


def response(flow: http.HTTPFlow):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client_ip": flow.client_conn.peername[0] if flow.client_conn.peername else None,
        "method": flow.request.method,
        "scheme": flow.request.scheme,
        "host": flow.request.pretty_host,
        "port": flow.request.port,
        "path": flow.request.path,
        "url": flow.request.pretty_url,
        "status_code": flow.response.status_code,
        "content_type": flow.response.headers.get("content-type", ""),
        "user_agent": flow.request.headers.get("user-agent", ""),
        "referer": flow.request.headers.get("referer", "")
    }

    logger.info(json.dumps(entry, ensure_ascii=False))
