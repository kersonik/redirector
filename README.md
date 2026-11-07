# Redirector

Lightweight Python/Flask service for smart link redirection, link cloaking, OpenGraph metadata spoofing, and GeoIP/telemetry logging.

## Features

- **Link Redirection**: Generate short tracking links with configurable targets and custom codes.
- **Link Cloaking**: Spoof OpenGraph title, description, and preview images for Discord, Telegram, Twitter, and Facebook crawlers.
- **GeoIP & Telemetry Logging**:
  - Client IP, country, city, and ISP detection
  - Browser and User-Agent parsing
  - Bot and crawler detection (identifies search engines, social media preview bots)
  - Optional GPS geolocation logging with accuracy metrics
- **Dashboard & Analytics**: In-app web interface for managing links, viewing access logs, and exporting telemetry data.
- **Zero Heavy Dependencies**: Built on Flask, SQLite, and Gunicorn.

## Stack

- **Backend**: Python 3.10+, Flask
- **Database**: SQLite (via `redirector.db` with auto-migration)
- **WSGI Server**: Gunicorn

## Installation & Setup

### 1. Clone & Set Up Environment

```bash
git clone https://github.com/kersonik/redirector.git
cd redirector

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Run Locally

```bash
python3 app.py
```

The application runs on `http://127.0.0.1:5000` by default.

### 3. Production Deployment (Systemd + Gunicorn)

1. Copy the example systemd unit:
   ```bash
   sudo cp redirector.service.example /etc/systemd/system/redirector.service
   ```
2. Edit `/etc/systemd/system/redirector.service` to match your user, working directory, and environment.
3. Enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now redirector.service
   ```

### 4. Reverse Proxy (Nginx Example)

```nginx
server {
    server_name r.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:5005;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Configuration

| Environment Variable | Default | Description |
| :--- | :--- | :--- |
| `DB_PATH` | `redirector.db` | Path to the SQLite database file |

## Security & Privacy Note

The SQLite database (`redirector.db`) stores IP addresses and access logs. Ensure appropriate retention policies and local database protection.
