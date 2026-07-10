import os
from dotenv import load_dotenv

load_dotenv()

ELASTIC_URL = os.getenv("ELASTIC_URL")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY")

# Investigation settings
# Index pattern for endpoint / system telemetry (Elastic Agent, Elastic Defend, Winlogbeat, etc.)
LOGS_INDEX = os.getenv("LOGS_INDEX", "logs-*")

# Time window around the alert timestamp (± minutes)
INVESTIGATION_WINDOW_MINUTES = int(
    os.getenv("INVESTIGATION_WINDOW_MINUTES", "5")
)

# Max documents returned per investigation query
INVESTIGATION_SIZE = int(os.getenv("INVESTIGATION_SIZE", "50"))

# LLM summary settings
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OPENAI_API_URL = os.getenv(
    "OPENAI_API_URL",
    "https://api.openai.com/v1/chat/completions",
)

# SOC report output folder
REPORTS_DIR = os.getenv("REPORTS_DIR", "reports")
SAVE_REPORTS = os.getenv("SAVE_REPORTS", "true").lower() in (
    "1",
    "true",
    "yes",
)

# IOC cache (SQLite)
CACHE_DB_PATH = os.getenv("CACHE_DB_PATH", "cache.db")
CACHE_TTL_HOURS = int(os.getenv("CACHE_TTL_HOURS", "24"))