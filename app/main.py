# =======================
# app/main.py  (AWS App Runner + single secret "YPC")
# =======================
from flask import Flask, request, jsonify, send_from_directory, g
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
import json
import os
import hmac
import logging
import sys

# Google/YouTube libs (unchanged)
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import isodate

# AWS: Secrets Manager
import boto3
from botocore.exceptions import ClientError

# -----------------------------------------------------------------------------
# Logging — send everything to stdout so App Runner/CloudWatch can capture it
# -----------------------------------------------------------------------------
class RequestFormatter(logging.Formatter):
    """Formatter that tolerates missing extra fields and adds simple request context."""
    def format(self, record):
        # Provide safe defaults for optional fields
        for key in ("method", "path", "status", "latency_ms", "client_ip"):
            if not hasattr(record, key):
                setattr(record, key, "-")
        return super().format(record)


def configure_logging():
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(RequestFormatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s "
        "[method=%(method)s path=%(path)s status=%(status)s latency_ms=%(latency_ms)s ip=%(client_ip)s]"
    ))

    root = logging.getLogger()
    # Remove any pre-attached handlers (Flask/Gunicorn may add their own)
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(handler)
    root.setLevel(log_level)

    # Quiet extremely chatty libraries if needed (optional)
    logging.getLogger("googleapiclient.discovery_cache").setLevel("WARNING")

    return root


root_logger = configure_logging()
logger = logging.getLogger("app")
logger.info("logger configured", extra={"method": "-", "path": "/", "status": "-"})

# -----------------------------------------------------------------------------
# Env & config
# -----------------------------------------------------------------------------
ENV = os.environ.get("ENV", "prod")  # "local" or "prod"
IS_LOCAL = ENV == "local"

REDIRECT_URI_LOCAL = os.environ.get("REDIRECT_URI_LOCAL", "http://localhost:8080/")
REDIRECT_URI_PROD = os.environ.get("REDIRECT_URI_PROD")  # set in App Runner env
REDIRECT_URI = REDIRECT_URI_LOCAL if IS_LOCAL else REDIRECT_URI_PROD

AWS_REGION = os.environ.get("AWS_REGION", "ap-southeast-1")

# Single combined secret (JSON) that contains both the Google client config and your API key
SECRET_NAME_COMBINED = os.environ.get("SECRET_NAME_COMBINED", "YPC")

app = Flask(__name__, static_folder="static")
# Align Flask's app.logger with our root handler/level
app.logger.handlers = logging.getLogger().handlers
app.logger.setLevel(logging.getLogger().level)

# -----------------------------------------------------------------------------
# Secrets loader (single secret "YPC")
# -----------------------------------------------------------------------------

def _parse_client_config(raw):
    """raw may be dict or a JSON string for Google OAuth client config."""
    if isinstance(raw, dict):
        return raw
    return json.loads(raw)


def load_secrets():
    """
    Loads Google OAuth client config and internal API key from one Secrets Manager
    secret (default name: YPC). Supports multiple key names.

    Expected secret JSON example:
    {
      "V2_CLIENT_JSON": "{...client json...}",   # or "client_json" / "client_config" (object or string)
      "V2_API_KEY": "your-api-key"               # or "api_key" / "API_KEY"
    }
    """
    sm = boto3.client("secretsmanager", region_name=AWS_REGION)
    try:
        resp = sm.get_secret_value(SecretId=SECRET_NAME_COMBINED)
        secret_str = resp.get("SecretString") or resp.get("SecretBinary", b"").decode("utf-8")
        data = json.loads(secret_str)
    except ClientError:
        logging.exception("Error fetching secret %s", SECRET_NAME_COMBINED)
        raise

    # Client config
    client_raw = data.get("V2_CLIENT_JSON") or data.get("client_json") or data.get("client_config")
    if client_raw is None:
        raise KeyError("Secret is missing client config (V2_CLIENT_JSON / client_json / client_config).")
    try:
        client_config = _parse_client_config(client_raw)
    except Exception as e:
        raise ValueError(f"Client config in secret is not valid JSON: {e}")

    # API key
    api_key = data.get("V2_API_KEY") or data.get("api_key") or data.get("API_KEY")
    if not api_key:
        raise KeyError("Secret is missing API key (V2_API_KEY / api_key / API_KEY).")

    return client_config, api_key.strip()


# -----------------------------------------------------------------------------
# Request logging hooks
# -----------------------------------------------------------------------------
@app.before_request
def _log_request_start():
    g._start = datetime.now(timezone.utc)
    app.logger.info(
        "➡️ request start",
        extra={
            "method": request.method,
            "path": request.path,
            "status": "-",
            "client_ip": request.headers.get("x-forwarded-for", request.remote_addr) or "-",
            "latency_ms": "-",
        },
    )


@app.after_request
def _log_request_end(response):
    started = getattr(g, "_start", None)
    latency_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000) if started else "-"
    app.logger.info(
        "✅ request end",
        extra={
            "method": request.method,
            "path": request.path,
            "status": response.status_code,
            "client_ip": request.headers.get("x-forwarded-for", request.remote_addr) or "-",
            "latency_ms": latency_ms,
        },
    )
    return response


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route("/check", methods=["GET"])
def check():
    app.logger.info("ℹ️ /check", extra={"method": request.method, "path": request.path})
    return "OK", 200


@app.route("/healthz", methods=["GET"])
def healthz():
    return {"ok": True}, 200


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def catch_all(path):
    app.logger.info("📥 Called / (path=%s)", path, extra={"method": request.method, "path": f"/{path}"})
    app.logger.info("🔍 ENV=%s IS_LOCAL=%s", ENV, IS_LOCAL, extra={"method": request.method, "path": f"/{path}"})
    return send_from_directory(app.static_folder, "index.html")


@app.route("/about", methods=["GET"])
def serve_pdf():
    return send_from_directory(app.static_folder, "about.pdf", mimetype="application/pdf")


@app.route("/create_playlist", methods=["POST"])
def create_playlist():
    try:
        data = request.get_json(silent=True) or {}
        code = data.get("code")
        competition_id = data.get("competition_id")
        earliest_date = data.get("earliest_date")
        incoming_api_key = request.headers.get("x-api-key")
        test_mode = (request.headers.get("X-Test-Mode", "true").lower() != "false")

        if not code or not competition_id or not earliest_date or not incoming_api_key:
            return jsonify({"error": "Missing required parameters"}), 400

        # ---- Load secrets (YPC) and validate API key ----
        client_config, api_key_secret = load_secrets()
        if not (incoming_api_key and hmac.compare_digest(incoming_api_key.strip(), api_key_secret)):
            return jsonify({"error": "Unauthorized"}), 403

        if not REDIRECT_URI:
            return jsonify({"error": "Server not configured with REDIRECT_URI"}), 500

        # ---- Singapore date math -> UTC cutoff (matches original intent) ----
        # Accepts ISO 8601 with/without 'Z', or just YYYY-MM-DD
        try:
            input_dt = datetime.fromisoformat(earliest_date.replace("Z", ""))
        except ValueError:
            input_dt = datetime.fromisoformat(earliest_date + "T00:00:00")

        now_sg = datetime.now(ZoneInfo("Asia/Singapore"))
        today_sg = now_sg.date()
        days_diff = (today_sg - input_dt.date()).days
        cutoff_datetime_utc = datetime.now(timezone.utc) - timedelta(days=days_diff) - timedelta(hours=24)
        cutoff_iso = cutoff_datetime_utc.isoformat(timespec="seconds").replace("+00:00", "Z")

        # ---- Google OAuth exchange + YouTube client ----
        flow = Flow.from_client_config(
            client_config,
            scopes=["https://www.googleapis.com/auth/youtube"],
            redirect_uri=REDIRECT_URI,
        )
        flow.fetch_token(code=code)
        creds: Credentials = flow.credentials
        youtube = build("youtube", "v3", credentials=creds)

        # ---- Test mode: probe API only ----
        if test_mode:
            try:
                test_call = youtube.channels().list(part="snippet", mine=True).execute()
                channel_title = (test_call.get("items") or [{}])[0].get("snippet", {}).get("title", "Unknown Channel")
                return jsonify(
                    {
                        "message": "✅ Test mode active — YouTube API is reachable",
                        "channel": channel_title,
                        "playlist_url": "https://www.youtube.com/playlist?list=TESTMODE123",
                    }
                ), 200
            except Exception:
                app.logger.exception("YouTube API test failed")
                return jsonify({"error": "❌ YouTube API test failed"}), 500

        # ---- Load channel map (bundled file) ----
        with open("app/channels.json", "r", encoding="utf-8") as f:
            CHANNEL_MAP = json.load(f)

        config = CHANNEL_MAP.get(competition_id)
        if not config:
            return jsonify({"error": "Unknown competition_id"}), 404

        channel_ids = config["channel_ids"]
        search_filter_raw = (config.get("search_filter") or "").strip()
        search_keywords = config.get("search_keywords", [])
        min_duration_seconds = int(config.get("min_duration_minutes", 2)) * 60

        # Build queries from search_filter (+ optional keywords)
        if search_filter_raw:
            queries = [search_filter_raw]
            if isinstance(search_keywords, list) and search_keywords:
                queries += [f"{search_filter_raw} {kw}".strip() for kw in search_keywords]
        else:
            queries = search_keywords if (isinstance(search_keywords, list) and search_keywords) else ["highlights"]

        # Region and pagination settings
        region_code = (request.headers.get("X-Region") or os.environ.get("YOUTUBE_REGION_CODE") or "SG").upper()
        max_pages = int(os.environ.get("YOUTUBE_MAX_PAGES", "4"))

        app.logger.info("🔧 Using queries=%s region=%s after=%s", queries, region_code, cutoff_iso,
                        extra={"method": request.method, "path": request.path})

        # ---- Find videos per channel since cutoff (uses search_filter as `q`) ----
        video_ids = []
        seen = set()

        for channel_id in channel_ids:
            for q in queries:
                app.logger.info("🔎 channel=%s q=%r", channel_id, q,
                                extra={"method": request.method, "path": request.path})
                page_token = None
                pages = 0

                while True:
                    try:
                        resp = youtube.search().list(
                            part="id,snippet",
                            channelId=channel_id,
                            q=q,                      # ← search_filter (and combos) used here
                            type="video",
                            order="date",            # newest → oldest within channel
                            maxResults=50,            # API limit
                            publishedAfter=cutoff_iso,
                            regionCode=region_code,
                            relevanceLanguage="en",   # optional; remove if you want all languages
                            pageToken=page_token,
                        ).execute()
                    except HttpError:
                        app.logger.exception("YouTube search failed",
                                             extra={"method": request.method, "path": request.path})
                        break

                    items = resp.get("items", [])
                    cand_ids = [it["id"].get("videoId") for it in items if it.get("id") and it["id"].get("videoId")]

                    if cand_ids:
                        try:
                            details = youtube.videos().list(
                                part="contentDetails",
                                id=",".join(cand_ids),
                            ).execute()
                        except HttpError:
                            app.logger.exception("videos.list failed for details",
                                                 extra={"method": request.method, "path": request.path})
                            details = {"items": []}

                        for v in details.get("items", []):
                            vid = v["id"]
                            dur_s = isodate.parse_duration(v["contentDetails"]["duration"]).total_seconds()
                            if dur_s > min_duration_seconds and vid not in seen:
                                seen.add(vid)
                                video_ids.append(vid)

                    page_token = resp.get("nextPageToken")
                    pages += 1
                    if not page_token or pages >= max_pages:
                        break

        if not video_ids:
            return jsonify({"message": "No matching highlight videos found.", "cutoff_iso": cutoff_iso}), 200

        # ---- Create playlist & add items ----
        playlist = youtube.playlists().insert(
            part="snippet,status",
            body={
                "snippet": {
                    "title": f"{competition_id} Highlights - {input_dt.date().isoformat()}",
                    "description": "Auto-generated playlist",
                },
                "status": {"privacyStatus": "unlisted"},
            },
        ).execute()

        playlist_id = playlist["id"]

        for vid in video_ids:
            youtube.playlistItems().insert(
                part="snippet",
                body={
                    "snippet": {
                        "playlistId": playlist_id,
                        "resourceId": {"kind": "youtube#video", "videoId": vid},
                    }
                },
            ).execute()

        return jsonify(
            {
                "playlist_url": f"https://www.youtube.com/playlist?list={playlist_id}",
                "video_count": len(video_ids),
                "cutoff_iso": cutoff_iso,
            }
        ), 200

    except Exception as e:
        app.logger.exception("Unhandled error in /create_playlist",
                             extra={"method": request.method, "path": request.path})
        return jsonify({"error": str(e)}), 500


# Gunicorn entrypoint for App Runner (local dev only)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
