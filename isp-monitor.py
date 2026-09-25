import os, time, subprocess, threading, csv, json, io, hashlib, secrets, re, smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
from flask import Flask, request, jsonify, session, redirect, send_from_directory, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
try:
    import psycopg2
except ImportError:
    psycopg2 = None

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'KMV_NETWORK_NOC_2026_SECURE_KEY_v2')
CORS(app)

@app.after_request
def add_no_cache_headers(response):
    """Keep browser rebuilds from showing old HTML/CSS/JS."""
    if response.content_type and 'text/html' in response.content_type:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    # Dashboard auto-refreshes every 10 s, so allow overriding the default limit.
    # Behind kubectl port-forward / Ingress every user shares one IP address.
    default_limits=[l.strip() for l in os.environ.get(
        'RATE_LIMIT_DEFAULT', '200 per day;50 per hour').split(';') if l.strip()]
)

@app.route('/healthz')
@limiter.exempt
def healthz():
    """Health check for Kubernetes probes (not rate-limited, no login)."""
    return jsonify(status='ok')

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SESSION_TIMEOUT_MINUTES = 30
MAX_LOGIN_ATTEMPTS = 5
LOGIN_ATTEMPT_TIMEOUT = 900  # 15 minutes
DEFAULT_SMTP_HOST = 'smtp.office365.com'
DEFAULT_SMTP_PORT = 587
DEFAULT_SMTP_USE_TLS = True
DEFAULT_SMTP_USE_SSL = False

def load_env_file():
    """Load local .env values without extra dependencies when running outside Docker."""
    env_path = os.path.join(BASE_DIR, '.env')
    if not os.path.exists(env_path):
        return
    try:
        with open(env_path, 'r', encoding='utf-8') as env_file:
            for line in env_file:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, value = line.split('=', 1)
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    except Exception as e:
        print(f"Could not load .env file: {e}")

load_env_file()

# --- USER ROLES & PERMISSIONS ---
ROLES = {
    'admin': {
        'description': 'Full system access',
        'permissions': ['view_sites', 'manage_users', 'manage_engineers', 'export_reports', 'view_logs']
    },
    'engineer': {
        'description': 'View assigned sites only',
        'permissions': ['view_sites', 'export_reports']
    },
    'viewer': {
        'description': 'Read-only access',
        'permissions': ['view_sites']
    }
}

# --- USER DATABASE (In-Memory, can be replaced with SQL) ---
users_db = {
    "admin": {
        "password_hash": generate_password_hash("admin123"),
        "email": "admin@kmv.com",
        "role": "admin",
        "full_name": "Administrator",
        "created_at": datetime.now().isoformat(),
        "last_login": None,
        "status": "active",
        "failed_attempts": 0,
        "locked_until": None,
        "password_reset_token": None,
        "password_reset_expires": None,
        "requires_password_change": False,
        "two_factor_enabled": False
    }
}

# Event & Audit Logs
downtime_logs = []
audit_logs = []
login_attempts = {}

# --- ZONES CONFIGURATION ---
ZONES = {
    'Central Zone': {
        'region_code': 'CZ',
        'description': 'Central Zone - Hyderabad, Vijayawada, Vizag',
        'manager': 'Paparao',
        'color': '#00e676'
    },
    'South': {
        'region_code': 'SR',
        'description': 'South Region - Bangalore, Karnataka',
        'manager': 'Vijay',
        'color': '#2196F3'
    },
    'North': {
        'region_code': 'NR',
        'description': 'North Region - Ranchi, Odisha, Jharkhand',
        'manager': 'Pavan',
        'color': '#FF9800'
    }
}

# --- ENGINEERS CONFIGURATION ---
ENGINEERS = {
    'Paparao': {
        'email': 'paparao.b@piersoft.com',
        'phone': '9XXXXXXXXX',
        'team_number': '',
        'region': 'Central Zone',
        'status': 'active'
    },
    'Vijay': {
        'email': 'vijaya.g@kmvgroup.com',
        'phone': '9XXXXXXXXX',
        'team_number': '',
        'region': 'South',
        'status': 'active'
    },
    'Pavan': {
        'email': 'pavankalyan.g@piersoft.com',
        'phone': '9XXXXXXXXX',
        'team_number': '',
        'region': 'North',
        'status': 'active'
    }
}

# --- FULL SITE CONFIGURATION ---
ISP_CONFIG = {
    # Central Zone - Assigned to Paparao
    'hyd_tata': {'region': 'Central Zone', 'name': 'Hyderabad - HO', 'ip': '115.108.34.237', 'isp': 'TATA', 'engineer': 'Paparao'},
    'hyd_bsnl': {'region': 'Central Zone', 'name': 'Hyderabad - HO', 'ip': '117.192.43.168', 'isp': 'BSNL', 'engineer': 'Paparao'},
    'hyd_pioneer': {'region': 'Central Zone', 'name': 'Hyderabad - HO', 'ip': '103.44.0.2', 'isp': 'Pioneer', 'engineer': 'Paparao'},
    'vja_beam': {'region': 'Central Zone', 'name': 'Vijayawada - Spaces', 'ip': '49.205.165.193', 'isp': 'BEAM', 'engineer': 'Paparao'},
    'vja_excel': {'region': 'Central Zone', 'name': 'Vijayawada - Spaces', 'ip': '175.101.79.148', 'isp': 'Excel', 'engineer': 'Paparao'},
    'central_yard': {'region': 'Central Zone', 'name': 'Central Yard', 'ip': '103.179.210.54', 'isp': 'SREE BB', 'engineer': 'Paparao'},
    'kdrp_1529': {'region': 'Central Zone', 'name': 'KDRP-1529', 'ip': '103.165.14.146', 'isp': 'City BB', 'engineer': 'Paparao'},
    'esi_vizag': {'region': 'Central Zone', 'name': 'ESI-Vizag', 'ip': '49.206.202.56', 'isp': 'ACT', 'engineer': 'Paparao'},
    'vit_mh6': {'region': 'Central Zone', 'name': 'VIT-MH6', 'ip': '117.250.205.124', 'isp': 'BSNL', 'engineer': 'Paparao'},
    'rvec_jio': {'region': 'Central Zone', 'name': 'RVEC-3 (Jio)', 'ip': '115.245.96.218', 'isp': 'Jio', 'engineer': 'Paparao'},
    'rvec_ishan': {'region': 'Central Zone', 'name': 'RVEC-3 (Ishan)', 'ip': '103.90.97.4', 'isp': 'Ishan', 'engineer': 'Paparao'},
    'naidu_peta': {'region': 'Central Zone', 'name': 'Naidu Peta', 'ip': '103.60.178.89', 'isp': 'Ishan', 'engineer': 'Paparao'},
    'gst_1549': {'region': 'Central Zone', 'name': 'GST-1549', 'ip': '183.82.111.203', 'isp': 'ACT', 'engineer': 'Paparao'},
    'npci_1548': {'region': 'Central Zone', 'name': 'NPCI-1548', 'ip': '183.82.101.55', 'isp': 'ACT', 'engineer': 'Paparao'},
    'apcrda_siti': {'region': 'Central Zone', 'name': 'APCRDA (SITI)', 'ip': '103.165.14.146', 'isp': 'SITI', 'engineer': 'Paparao'},
    'apcrda_sree': {'region': 'Central Zone', 'name': 'APCRDA (SREE)', 'ip': '103.179.210.61', 'isp': 'SREE BB', 'engineer': 'Paparao'},
    'amns_jio': {'region': 'Central Zone', 'name': 'AMNS (Jio)', 'ip': '115.245.247.230', 'isp': 'Jio', 'engineer': 'Paparao'},
    'thane_tata': {'region': 'Central Zone', 'name': 'THANE (TATA)', 'ip': '108.80.162.226', 'isp': 'TATA', 'engineer': 'Paparao'},
    
    # South Region - Assigned to Vijay
    'blr_airtel': {'region': 'South', 'name': 'BANGALORE NEW RO', 'ip': '122.166.3.152', 'isp': 'Airtel', 'engineer': 'Vijay'},
    'blr_act': {'region': 'South', 'name': 'BANGALORE NEW RO', 'ip': '106.51.185.105', 'isp': 'ACT', 'engineer': 'Vijay'},
    'koppal_jio': {'region': 'South', 'name': 'Koppal Hospital', 'ip': '139.167.43.158', 'isp': 'Jio', 'engineer': 'Vijay'},
    'chik_bsnl': {'region': 'South', 'name': 'Chikkanahally', 'ip': '103.186.40.65', 'isp': 'BSNL', 'engineer': 'Vijay'},
    'yadgiri_bsnl': {'region': 'South', 'name': 'Yadgiri', 'ip': '103.21.232.15', 'isp': 'BSNL', 'engineer': 'Vijay'},
    'byap_airtel': {'region': 'South', 'name': 'Byapanahally', 'ip': '122.166.3.152', 'isp': 'Airtel', 'engineer': 'Vijay'},
    'byap_tikona': {'region': 'South', 'name': 'Byapanahally', 'ip': '1.23.215.7', 'isp': 'TIKONA', 'engineer': 'Vijay'},
    'kukkan_jio': {'region': 'South', 'name': 'Kukkanahally', 'ip': '139.167.43.158', 'isp': 'Jio', 'engineer': 'Vijay'},
    'hubli_airtel': {'region': 'South', 'name': 'Hubli', 'ip': '122.166.77.61', 'isp': 'Airtel', 'engineer': 'Vijay'},
    'apcpwd_jio': {'region': 'South', 'name': 'APCPWD CENTRAL', 'ip': '115.245.247.230', 'isp': 'Jio', 'engineer': 'Vijay'},
    'raichur_bsnl': {'region': 'South', 'name': 'Raichur-2232', 'ip': '117.254.104.2', 'isp': 'BSNL', 'engineer': 'Vijay'},
    'belgavi_bsnl': {'region': 'South', 'name': 'Belgavi-2237', 'ip': '117.220.197.115', 'isp': 'BSNL', 'engineer': 'Vijay'},
    'jewargi_jio': {'region': 'South', 'name': 'Jewargi-2240', 'ip': '139.167.43.158', 'isp': 'Jio', 'engineer': 'Vijay'},
    
    # North Region - Assigned to Pavan
    'ran_iffco': {'region': 'North', 'name': 'Iffco Paradeep', 'ip': '115.245.247.230', 'isp': 'Jio', 'engineer': 'Pavan'},
    'ran_trans': {'region': 'North', 'name': 'Transport Nagar', 'ip': '117.247.75.110', 'isp': 'BSNL', 'engineer': 'Pavan'},
    'ran_mla': {'region': 'North', 'name': 'MLA Quarters', 'ip': '115.245.247.230', 'isp': 'Jio', 'engineer': 'Pavan'},
    'ran_chaib': {'region': 'North', 'name': 'Chaibhasa', 'ip': '115.245.188.222', 'isp': 'Jio', 'engineer': 'Pavan'},
    'ran_mgm': {'region': 'North', 'name': 'MGM Hospital', 'ip': '223.235.84.190', 'isp': 'Airtel', 'engineer': 'Pavan'},
    'ran_pabhoi': {'region': 'North', 'name': 'Pabhoi- 9003', 'ip': '115.245.126.110', 'isp': 'Jio', 'engineer': 'Pavan'},
    'ran_rknag': {'region': 'North', 'name': 'R.K Nagar- 9005', 'ip': '115.245.247.230', 'isp': 'Jio', 'engineer': 'Pavan'},
    'ran_pola': {'region': 'North', 'name': 'Polavaram- 1080', 'ip': '103.179.210.61', 'isp': 'AP Fiber', 'engineer': 'Pavan'},
    'ran_bok_air': {'region': 'North', 'name': 'Bokaro (Airtel)', 'ip': '110.227.196.67', 'isp': 'Airtel', 'engineer': 'Pavan'},
    'ran_bok_ibex': {'region': 'North', 'name': 'Bokaro (Ibex)', 'ip': '103.165.14.146', 'isp': 'Ibex', 'engineer': 'Pavan'},
    'ran_ro': {'region': 'North', 'name': 'Ranchi RO- 16003', 'ip': '122.179.193.118', 'isp': 'Airtel', 'engineer': 'Pavan'}
}

status_cache = {k: {'status': 'checking', 'latency': 0, 'ts': '--'} for k in ISP_CONFIG}
DELETED_SITE_IDS = set()

# --- HELPER FUNCTIONS ---

def log_audit(username, action, details, status='success'):
    """Log user actions for audit trail"""
    audit_logs.insert(0, {
        'timestamp': datetime.now().isoformat(),
        'username': username,
        'action': action,
        'details': details,
        'status': status,
        'ip_address': request.remote_addr
    })
    if len(audit_logs) > 1000:
        audit_logs.pop()

def check_session_timeout():
    """Check if session has expired"""
    if 'login_time' in session:
        elapsed = datetime.now() - datetime.fromisoformat(session['login_time'])
        if elapsed > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
            session.clear()
            return False
    return True

def require_login(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('loggedIn') or not check_session_timeout():
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

def require_role(required_role):
    """Decorator to require specific role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('loggedIn'):
                return jsonify({'error': 'Unauthorized'}), 401
            user_role = session.get('user_role')
            if user_role != required_role and user_role != 'admin':
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def is_valid_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_strong_password(password):
    """Check password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not any(c.isupper() for c in password):
        return False, "Password must contain uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain digit"
    if not any(c in '!@#$%^&*' for c in password):
        return False, "Password must contain special character (!@#$%^&*)"
    return True, "Password is strong"

def generate_reset_token():
    """Generate secure password reset token"""
    return secrets.token_urlsafe(32)

def get_base_url():
    configured_url = os.environ.get('APP_BASE_URL')
    if configured_url:
        return configured_url.rstrip('/')
    return request.host_url.rstrip('/')

def config_bool(value, default=False):
    """Read booleans consistently from saved JSON values and environment strings."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ('1', 'true', 'yes', 'on')

def get_mail_settings():
    saved_settings = {}
    try:
        saved_settings = load_state_from_db('mail_settings') or {}
    except Exception:
        saved_settings = {}

    if not saved_settings:
        try:
            mail_file = os.path.join(BASE_DIR, 'data', 'mail_settings.json')
            if os.path.exists(mail_file):
                with open(mail_file, 'r') as f:
                    saved_settings = json.load(f) or {}
        except Exception:
            saved_settings = {}

    smtp_port = int(saved_settings.get('smtp_port') or os.environ.get('SMTP_PORT') or DEFAULT_SMTP_PORT)
    smtp_use_tls = config_bool(saved_settings.get('smtp_use_tls'), config_bool(os.environ.get('SMTP_USE_TLS'), DEFAULT_SMTP_USE_TLS))
    smtp_use_ssl = config_bool(saved_settings.get('smtp_use_ssl'), config_bool(os.environ.get('SMTP_USE_SSL'), DEFAULT_SMTP_USE_SSL))

    # Auto-correct: if both flags are set, pick the correct one based on port
    if smtp_use_ssl and smtp_use_tls:
        smtp_use_ssl = (smtp_port == 465)
        smtp_use_tls = not smtp_use_ssl

    return {
        'smtp_host': saved_settings.get('smtp_host') or os.environ.get('SMTP_HOST') or DEFAULT_SMTP_HOST,
        'smtp_port': smtp_port,
        'smtp_user': saved_settings.get('smtp_user') or os.environ.get('SMTP_USER') or '',
        'smtp_password': saved_settings.get('smtp_password') or os.environ.get('SMTP_PASSWORD') or '',
        'smtp_from': saved_settings.get('smtp_from') or os.environ.get('SMTP_FROM') or saved_settings.get('smtp_user') or os.environ.get('SMTP_USER') or '',
        'smtp_use_tls': smtp_use_tls,
        'smtp_use_ssl': smtp_use_ssl,
        'alerts_enabled': config_bool(saved_settings.get('alerts_enabled'), config_bool(os.environ.get('MAIL_ALERTS_ENABLED'), False)),
        'alert_recipients': saved_settings.get('alert_recipients') or os.environ.get('MAIL_ALERT_RECIPIENTS') or '',
        'alert_on_recovery': config_bool(saved_settings.get('alert_on_recovery'), config_bool(os.environ.get('MAIL_ALERT_ON_RECOVERY'), True)),
    }

def send_email(to_emails, subject, text_body, html_body=None):
    """Send an email using the configured SMTP server."""
    mail_settings = get_mail_settings()
    smtp_host = mail_settings['smtp_host']
    smtp_port = mail_settings['smtp_port']
    smtp_user = mail_settings['smtp_user']
    smtp_password = mail_settings['smtp_password']
    smtp_from = mail_settings['smtp_from']
    smtp_use_tls = mail_settings['smtp_use_tls']
    smtp_use_ssl = mail_settings['smtp_use_ssl']

    if not smtp_host or not smtp_from:
        return False, 'SMTP is not configured'

    if isinstance(to_emails, str):
        recipients = [email.strip() for email in to_emails.split(',') if email.strip()]
    else:
        recipients = [str(email).strip() for email in to_emails if str(email).strip()]

    invalid_emails = [email for email in recipients if not is_valid_email(email)]
    if not recipients:
        return False, 'No email recipients configured'
    if invalid_emails:
        return False, f"Invalid email recipients: {', '.join(invalid_emails)}"

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = smtp_from
    msg['To'] = ', '.join(recipients)
    msg.set_content(text_body)
    if html_body:
        msg.add_alternative(html_body, subtype='html')

    try:
        smtp_class = smtplib.SMTP_SSL if smtp_use_ssl else smtplib.SMTP
        with smtp_class(smtp_host, smtp_port, timeout=15) as smtp:
            if smtp_use_tls and not smtp_use_ssl:
                smtp.starttls()
            if smtp_user and smtp_password:
                smtp.login(smtp_user, smtp_password)
            smtp.send_message(msg)
        return True, None
    except smtplib.SMTPAuthenticationError as e:
        code = e.smtp_code
        msg_bytes = e.smtp_error if isinstance(e.smtp_error, str) else e.smtp_error.decode('utf-8', errors='replace')
        if code == 535 and '5.7.139' in msg_bytes:
            return False, (
                'Office 365 SMTP AUTH is disabled for this mailbox. '
                'Fix: M365 Admin Center → Users → Active Users → select the user → '
                'Mail tab → Manage email apps → enable "Authenticated SMTP" → Save. '
                'Then wait 5–10 minutes and retry.'
            )
        if code in (535, 534, 530):
            return False, f'Authentication failed (code {code}). Check your SMTP username and password.'
        return False, f'SMTP auth error {code}: {msg_bytes}'
    except smtplib.SMTPConnectError as e:
        return False, f'Cannot connect to {smtp_host}:{smtp_port} — check host and port. ({e})'
    except smtplib.SMTPException as e:
        return False, f'SMTP error: {e}'
    except OSError as e:
        if 'WRONG_VERSION_NUMBER' in str(e):
            mode = 'SSL (port 465)' if smtp_use_ssl else 'STARTTLS (port 587)'
            return False, f'SSL version mismatch: port {smtp_port} does not support {mode}. Switch connection security to match the port.'
        return False, f'Connection error: {e}'
    except Exception as e:
        return False, str(e)

def send_password_reset_email(email, reset_url):
    """Send password reset email if SMTP settings are configured."""
    subject = 'KMV Network Monitor Password Reset'
    text_body = (
        "Hello,\n\n"
        "A password reset was requested for your KMV Network Monitor account.\n\n"
        f"Reset your password here:\n{reset_url}\n\n"
        "This link expires in 1 hour. If you did not request this, ignore this email.\n"
    )
    html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; color: #1f2937;">
                <h2>KMV Network Monitor Password Reset</h2>
                <p>A password reset was requested for your KMV Network Monitor account.</p>
                <p>
                    <a href="{reset_url}" style="background:#0ea5e9;color:#ffffff;padding:10px 16px;text-decoration:none;border-radius:4px;display:inline-block;">
                        Reset Password
                    </a>
                </p>
                <p>This link expires in 1 hour. If you did not request this, ignore this email.</p>
                <p style="font-size:12px;color:#64748b;">{reset_url}</p>
            </body>
        </html>
    """
    return send_email(email, subject, text_body, html_body)

def send_link_status_alert(site_key, new_status, old_status):
    """Send link-down and optional recovery alerts on confirmed status transitions."""
    mail_settings = get_mail_settings()
    if not mail_settings['alerts_enabled']:
        return
    if new_status == 'online' and not mail_settings['alert_on_recovery']:
        return

    config = ISP_CONFIG.get(site_key)
    if not config:
        return

    alert_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    is_down = new_status == 'offline'
    subject_status = 'Link Down Alert' if is_down else 'Link Restored'
    subject = f"KMV {subject_status} - {config.get('name', site_key)}"
    text_body = (
        f"KMV Network Monitor {subject_status}\n\n"
        f"Site: {config.get('name', site_key)}\n"
        f"IP Address: {config.get('ip', '-')}\n"
        f"Zone: {config.get('region', '-')}\n"
        f"ISP Name: {config.get('isp', '-')}\n"
        f"Engineer: {config.get('engineer', '-')}\n"
        f"Old Status: {old_status}\n"
        f"Current Status: {new_status.upper()}\n"
        f"Time: {alert_time}\n"
    )
    status_color = '#dc2626' if is_down else '#16a34a'
    html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; color: #1f2937;">
                <h2 style="color:{status_color};">KMV Network Monitor {subject_status}</h2>
                <table cellpadding="6" cellspacing="0" style="border-collapse:collapse;">
                    <tr><td><strong>Site</strong></td><td>{config.get('name', site_key)}</td></tr>
                    <tr><td><strong>IP Address</strong></td><td>{config.get('ip', '-')}</td></tr>
                    <tr><td><strong>Zone</strong></td><td>{config.get('region', '-')}</td></tr>
                    <tr><td><strong>ISP Name</strong></td><td>{config.get('isp', '-')}</td></tr>
                    <tr><td><strong>Engineer</strong></td><td>{config.get('engineer', '-')}</td></tr>
                    <tr><td><strong>Old Status</strong></td><td>{old_status}</td></tr>
                    <tr><td><strong>Current Status</strong></td><td style="color:{status_color};font-weight:bold;">{new_status.upper()}</td></tr>
                    <tr><td><strong>Time</strong></td><td>{alert_time}</td></tr>
                </table>
            </body>
        </html>
    """
    sent, error = send_email(mail_settings['alert_recipients'], subject, text_body, html_body)
    if not sent:
        print(f"Mail alert failed for {site_key}: {error}")

# --- PING ENGINE ---

def log_event(site_key, status):
    config = ISP_CONFIG[site_key]
    event = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'site': config['name'],
        'region': config['region'],
        'isp': config['isp'],
        'engineer': config['engineer'],
        'status': status
    }
    downtime_logs.insert(0, event)
    if len(downtime_logs) > 500:
        downtime_logs.pop()

def ping_site(key, ip):
    try:
        res = subprocess.run(['ping', '-c', '1', '-W', '1', ip], stdout=subprocess.PIPE, text=True, timeout=2)
        new_status = 'online' if (res.returncode == 0 and 'time=' in res.stdout) else 'offline'
        old_status = status_cache[key]['status']
        if old_status != new_status and old_status != 'checking':
            log_event(key, new_status)
            send_link_status_alert(key, new_status, old_status)
        ms = float(res.stdout.split('time=')[1].split()[0].replace('ms', '')) if new_status == 'online' else 0
        return key, new_status, round(ms, 1)
    except:
        old_status = status_cache[key]['status']
        if old_status != 'offline' and old_status != 'checking':
            log_event(key, 'offline')
            send_link_status_alert(key, 'offline', old_status)
        return key, 'offline', 0

def ping_worker():
    while True:
        with ThreadPoolExecutor(max_workers=40) as executor:
            futures = [executor.submit(ping_site, k, v['ip']) for k, v in ISP_CONFIG.items()]
            for f in as_completed(futures):
                key, status, ms = f.result()
                if key in ISP_CONFIG:
                    status_cache[key] = {'status': status, 'latency': ms, 'ts': datetime.now().strftime("%H:%M:%S")}
        time.sleep(15)

# --- AUTHENTICATION ROUTES ---

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    """User login with brute force protection"""
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    # Check brute force
    if username in login_attempts:
        attempts, locked_time = login_attempts[username]
        if locked_time and datetime.now() < locked_time:
            return jsonify({'error': 'Account temporarily locked. Try again later.'}), 429
    
    if username not in users_db:
        log_audit(username, 'LOGIN_FAILED', 'User not found', 'failed')
        return jsonify({'error': 'Invalid credentials'}), 401
    
    user = users_db[username]
    
    # Check if account is locked
    if user['locked_until'] and datetime.now() < datetime.fromisoformat(user['locked_until']):
        return jsonify({'error': 'Account is locked. Contact administrator.'}), 403
    
    # Check if account is active
    if user['status'] != 'active':
        return jsonify({'error': 'Account is inactive'}), 403
    
    # Verify password
    if not check_password_hash(user['password_hash'], password):
        user['failed_attempts'] = user.get('failed_attempts', 0) + 1
        if user['failed_attempts'] >= MAX_LOGIN_ATTEMPTS:
            user['locked_until'] = (datetime.now() + timedelta(seconds=LOGIN_ATTEMPT_TIMEOUT)).isoformat()
            log_audit(username, 'ACCOUNT_LOCKED', 'Too many failed attempts', 'failed')
            return jsonify({'error': 'Account locked due to too many failed attempts'}), 403
        log_audit(username, 'LOGIN_FAILED', f'Invalid password (attempt {user["failed_attempts"]})', 'failed')
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Successful login
    user['failed_attempts'] = 0
    user['locked_until'] = None
    user['last_login'] = datetime.now().isoformat()
    save_runtime_config()
    
    session['loggedIn'] = True
    session['username'] = username
    session['user_role'] = user['role']
    session['login_time'] = datetime.now().isoformat()
    
    log_audit(username, 'LOGIN_SUCCESS', f'Logged in from {request.remote_addr}', 'success')
    
    return jsonify({
        'success': True,
        'username': username,
        'role': user['role'],
        'requires_password_change': user.get('requires_password_change', False)
    })

@app.route('/api/auth/logout', methods=['POST'])
@require_login
def logout():
    """User logout"""
    username = session.get('username')
    log_audit(username, 'LOGOUT', 'User logged out', 'success')
    session.clear()
    return jsonify({'success': True})

@app.route('/api/auth/profile', methods=['GET'])
@require_login
def get_profile():
    """Get current user profile"""
    username = session.get('username')
    user = users_db.get(username)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'username': username,
        'email': user['email'],
        'full_name': user['full_name'],
        'role': user['role'],
        'status': user['status'],
        'last_login': user['last_login'],
        'created_at': user['created_at'],
        'two_factor_enabled': user.get('two_factor_enabled', False)
    })

@app.route('/api/auth/profile', methods=['PUT'])
@require_login
def update_profile():
    """Update current user profile."""
    username = session.get('username')
    user = users_db.get(username)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.json or {}
    email = (data.get('email') or '').strip()
    full_name = (data.get('full_name') or '').strip()

    if not full_name:
        return jsonify({'error': 'Full name is required'}), 400
    if not email or not is_valid_email(email):
        return jsonify({'error': 'Valid email is required'}), 400

    user['email'] = email
    user['full_name'] = full_name
    save_runtime_config()
    log_audit(username, 'PROFILE_UPDATED', 'User updated profile', 'success')

    return jsonify({
        'success': True,
        'message': 'Profile updated successfully',
        'profile': {
            'username': username,
            'email': user['email'],
            'full_name': user['full_name'],
            'role': user['role'],
            'status': user['status']
        }
    })

@app.route('/api/auth/change-password', methods=['POST'])
@require_login
def change_password():
    """Change user password"""
    username = session.get('username')
    data = request.json
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')
    
    user = users_db.get(username)
    
    # Verify current password
    if not check_password_hash(user['password_hash'], current_password):
        log_audit(username, 'PASSWORD_CHANGE_FAILED', 'Invalid current password', 'failed')
        return jsonify({'error': 'Current password is incorrect'}), 401
    
    # Check password confirmation
    if new_password != confirm_password:
        return jsonify({'error': 'Passwords do not match'}), 400
    
    # Validate new password strength
    is_strong, message = is_strong_password(new_password)
    if not is_strong:
        return jsonify({'error': message}), 400
    
    # Check if new password is same as old
    if check_password_hash(user['password_hash'], new_password):
        return jsonify({'error': 'New password must be different from current password'}), 400
    
    # Update password
    user['password_hash'] = generate_password_hash(new_password)
    user['requires_password_change'] = False
    log_audit(username, 'PASSWORD_CHANGED', 'User changed password', 'success')
    save_runtime_config()
    
    return jsonify({'success': True, 'message': 'Password changed successfully'})

@app.route('/api/auth/forgot-password', methods=['POST'])
@limiter.limit("3 per hour")
def forgot_password():
    """Request password reset"""
    data = request.json
    email = data.get('email', '').strip()
    
    # Find user by email
    user_found = None
    username_found = None
    for uname, user in users_db.items():
        if user['email'].lower() == email.lower():
            user_found = user
            username_found = uname
            break
    
    if not user_found:
        # Don't reveal if email exists (security)
        log_audit('unknown', 'PASSWORD_RESET_ATTEMPT', f'Email: {email}', 'failed')
        return jsonify({'success': True, 'message': 'If email exists, reset link has been sent'})
    
    # Generate reset token
    reset_token = generate_reset_token()
    user_found['password_reset_token'] = reset_token
    user_found['password_reset_expires'] = (datetime.now() + timedelta(hours=1)).isoformat()
    
    log_audit(username_found, 'PASSWORD_RESET_REQUESTED', f'Reset token generated', 'success')
    save_runtime_config()
    
    reset_url = f"{get_base_url()}/reset-password?token={reset_token}"
    mail_sent, mail_error = send_password_reset_email(email, reset_url)
    if not mail_sent:
        log_audit(username_found, 'PASSWORD_RESET_EMAIL_FAILED', mail_error or 'SMTP not configured', 'failed')
    
    response = {
        'success': True,
        'message': 'Password reset link sent to email' if mail_sent else 'Reset link generated, but email is not configured',
        'mail_sent': mail_sent
    }
    if not mail_sent:
        response['reset_url'] = reset_url
        response['mail_error'] = mail_error
    return jsonify(response)

@app.route('/api/auth/reset-password', methods=['POST'])
@limiter.limit("3 per hour")
def reset_password():
    """Reset password with token"""
    data = request.json
    reset_token = data.get('token')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')
    
    # Find user with token
    user_found = None
    username_found = None
    for uname, user in users_db.items():
        if user.get('password_reset_token') == reset_token:
            user_found = user
            username_found = uname
            break
    
    if not user_found:
        return jsonify({'error': 'Invalid or expired reset token'}), 400
    
    # Check if token is expired
    if not user_found['password_reset_expires']:
        return jsonify({'error': 'Reset token has expired'}), 400
    
    if datetime.now() > datetime.fromisoformat(user_found['password_reset_expires']):
        user_found['password_reset_token'] = None
        user_found['password_reset_expires'] = None
        return jsonify({'error': 'Reset token has expired'}), 400
    
    # Check password confirmation
    if new_password != confirm_password:
        return jsonify({'error': 'Passwords do not match'}), 400
    
    # Validate password strength
    is_strong, message = is_strong_password(new_password)
    if not is_strong:
        return jsonify({'error': message}), 400
    
    # Update password
    user_found['password_hash'] = generate_password_hash(new_password)
    user_found['password_reset_token'] = None
    user_found['password_reset_expires'] = None
    user_found['failed_attempts'] = 0
    user_found['locked_until'] = None
    
    log_audit(username_found, 'PASSWORD_RESET_SUCCESS', 'Password reset via token', 'success')
    save_runtime_config()
    
    return jsonify({'success': True, 'message': 'Password has been reset successfully'})

# --- USER MANAGEMENT ROUTES (ADMIN ONLY) ---

@app.route('/api/admin/users', methods=['GET'])
@require_login
@require_role('admin')
def get_users():
    """Get all users (admin only)"""
    users_list = []
    for username, user in users_db.items():
        users_list.append({
            'username': username,
            'email': user['email'],
            'full_name': user['full_name'],
            'role': user['role'],
            'status': user['status'],
            'last_login': user['last_login'],
            'created_at': user['created_at'],
            'failed_attempts': user.get('failed_attempts', 0),
            'two_factor_enabled': user.get('two_factor_enabled', False)
        })
    return jsonify(users_list)

@app.route('/api/admin/users/create', methods=['POST'])
@require_login
@require_role('admin')
def create_user():
    """Create new user (admin only)"""
    data = request.json
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    full_name = data.get('full_name', '').strip()
    role = data.get('role', 'viewer')
    temporary_password = data.get('temporary_password') or secrets.token_urlsafe(12)
    
    # Validation
    if not username or len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    
    if username in users_db:
        return jsonify({'error': 'Username already exists'}), 400
    
    if not is_valid_email(email):
        return jsonify({'error': 'Invalid email format'}), 400
    
    if role not in ROLES:
        return jsonify({'error': f'Invalid role. Must be one of: {list(ROLES.keys())}'}), 400
    
    # Create user
    users_db[username] = {
        'password_hash': generate_password_hash(temporary_password),
        'email': email,
        'role': role,
        'full_name': full_name,
        'created_at': datetime.now().isoformat(),
        'last_login': None,
        'status': 'active',
        'failed_attempts': 0,
        'locked_until': None,
        'password_reset_token': None,
        'password_reset_expires': None,
        'requires_password_change': True,
        'two_factor_enabled': False
    }
    
    log_audit(session.get('username'), 'USER_CREATED', f'Created user: {username} with role: {role}', 'success')
    save_runtime_config()
    
    return jsonify({
        'success': True,
        'message': 'User created successfully',
        'username': username,
        'temporary_password': temporary_password,
        'requires_password_change': True
    }), 201

@app.route('/api/admin/users/<username>/edit', methods=['PUT'])
@require_login
@require_role('admin')
def edit_user(username):
    """Edit user (admin only)"""
    if username not in users_db:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.json
    user = users_db[username]
    
    # Update allowed fields
    if 'email' in data:
        email = data['email'].strip()
        if not is_valid_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        user['email'] = email
    
    if 'full_name' in data:
        user['full_name'] = data['full_name'].strip()
    
    if 'role' in data:
        if data['role'] not in ROLES:
            return jsonify({'error': f'Invalid role'}), 400
        user['role'] = data['role']
    
    if 'status' in data:
        if data['status'] not in ['active', 'inactive']:
            return jsonify({'error': 'Invalid status'}), 400
        user['status'] = data['status']
    
    log_audit(session.get('username'), 'USER_UPDATED', f'Updated user: {username}', 'success')
    save_runtime_config()
    
    return jsonify({'success': True, 'message': f'User {username} updated successfully'})

@app.route('/api/admin/users/<username>/reset-password', methods=['POST'])
@require_login
@require_role('admin')
def admin_reset_password(username):
    """Reset user password (admin only) — accepts new_password in request body"""
    if username not in users_db:
        return jsonify({'error': 'User not found'}), 404

    data = request.json or {}
    new_password = data.get('new_password', '').strip()
    if not new_password:
        return jsonify({'error': 'new_password is required'}), 400

    ok, msg = is_strong_password(new_password)
    if not ok:
        return jsonify({'error': msg}), 400

    user = users_db[username]
    user['password_hash'] = generate_password_hash(new_password)
    user['requires_password_change'] = False
    user['failed_attempts'] = 0
    user['locked_until'] = None

    log_audit(session.get('username'), 'USER_PASSWORD_RESET', f'Admin reset password for: {username}', 'success')
    save_runtime_config()

    return jsonify({'success': True, 'message': f'Password reset for {username}'})

@app.route('/api/admin/users/<username>/lock', methods=['POST'])
@require_login
@require_role('admin')
def lock_user(username):
    """Lock user account (admin only)"""
    if username not in users_db:
        return jsonify({'error': 'User not found'}), 404
    
    if username == session.get('username'):
        return jsonify({'error': 'Cannot lock your own account'}), 400
    
    user = users_db[username]
    user['status'] = 'inactive'
    
    log_audit(session.get('username'), 'USER_LOCKED', f'Locked account: {username}', 'success')
    save_runtime_config()
    
    return jsonify({'success': True, 'message': f'User {username} has been locked'})

@app.route('/api/admin/users/<username>/unlock', methods=['POST'])
@require_login
@require_role('admin')
def unlock_user(username):
    """Unlock user account (admin only)"""
    if username not in users_db:
        return jsonify({'error': 'User not found'}), 404
    
    user = users_db[username]
    user['status'] = 'active'
    user['failed_attempts'] = 0
    user['locked_until'] = None
    
    log_audit(session.get('username'), 'USER_UNLOCKED', f'Unlocked account: {username}', 'success')
    save_runtime_config()
    
    return jsonify({'success': True, 'message': f'User {username} has been unlocked'})

@app.route('/api/admin/mail-settings', methods=['GET'])
@require_login
@require_role('admin')
def get_mail_settings_api():
    """Get SMTP mail settings for password reset emails."""
    settings = get_mail_settings()
    return jsonify({
        'smtp_host': settings['smtp_host'],
        'smtp_port': settings['smtp_port'],
        'smtp_user': settings['smtp_user'],
        'smtp_from': settings['smtp_from'],
        'smtp_use_tls': settings['smtp_use_tls'],
        'smtp_use_ssl': settings['smtp_use_ssl'],
        'alerts_enabled': settings['alerts_enabled'],
        'alert_recipients': settings['alert_recipients'],
        'alert_on_recovery': settings['alert_on_recovery'],
        'password_configured': bool(settings['smtp_password'])
    })

@app.route('/api/admin/mail-settings', methods=['PUT'])
@require_login
@require_role('admin')
def save_mail_settings_api():
    """Save SMTP mail settings for password reset emails."""
    data = request.json or {}
    existing = get_mail_settings()

    smtp_host = (data.get('smtp_host') or '').strip()
    smtp_port = int(data.get('smtp_port') or 587)
    smtp_user = (data.get('smtp_user') or '').strip()
    smtp_from = (data.get('smtp_from') or smtp_user).strip()
    smtp_password = data.get('smtp_password')
    alert_recipients = (data.get('alert_recipients') or '').strip()

    smtp_use_ssl = bool(data.get('smtp_use_ssl'))
    smtp_use_tls = bool(data.get('smtp_use_tls'))

    if not smtp_host:
        return jsonify({'error': 'SMTP host is required'}), 400
    if smtp_port <= 0:
        return jsonify({'error': 'SMTP port is invalid'}), 400
    if not smtp_from or not is_valid_email(smtp_from):
        return jsonify({'error': 'Valid from email is required'}), 400
    if smtp_user and not is_valid_email(smtp_user):
        return jsonify({'error': 'SMTP username must be a valid email'}), 400
    if smtp_use_ssl and smtp_use_tls:
        return jsonify({'error': 'SSL and STARTTLS cannot both be enabled. Use SSL on port 465 or STARTTLS on port 587.'}), 400
    if smtp_use_ssl and smtp_port == 587:
        return jsonify({'error': 'Port 587 uses STARTTLS, not SSL. Use port 465 for SSL, or switch to STARTTLS.'}), 400
    if smtp_use_tls and smtp_port == 465:
        return jsonify({'error': 'Port 465 uses SSL, not STARTTLS. Use port 587 for STARTTLS, or switch to SSL.'}), 400
    if data.get('alerts_enabled'):
        recipients = [email.strip() for email in alert_recipients.split(',') if email.strip()]
        if not recipients:
            return jsonify({'error': 'Add at least one alert recipient'}), 400
        invalid_recipients = [email for email in recipients if not is_valid_email(email)]
        if invalid_recipients:
            return jsonify({'error': f"Invalid alert recipient: {', '.join(invalid_recipients)}"}), 400

    settings = {
        'smtp_host': smtp_host,
        'smtp_port': smtp_port,
        'smtp_user': smtp_user,
        'smtp_from': smtp_from,
        'smtp_password': smtp_password if smtp_password else existing.get('smtp_password', ''),
        'smtp_use_tls': smtp_use_tls,
        'smtp_use_ssl': smtp_use_ssl,
        'alerts_enabled': bool(data.get('alerts_enabled')),
        'alert_recipients': alert_recipients,
        'alert_on_recovery': bool(data.get('alert_on_recovery'))
    }

    save_state_to_db('mail_settings', settings)

    try:
        with open(MAIL_SETTINGS_FILE, 'w') as f:
            json.dump(settings, f, indent=2)
    except Exception as e:
        print(f"Could not save mail settings to file: {e}")
        return jsonify({'error': f'Could not save mail settings: {e}'}), 500

    log_audit(session.get('username'), 'MAIL_SETTINGS_UPDATED', f'Updated SMTP host: {smtp_host}', 'success')
    return jsonify({'success': True, 'message': 'Mail settings saved successfully'})

@app.route('/api/admin/mail-settings/test', methods=['POST'])
@require_login
@require_role('admin')
def test_mail_settings_api():
    """Send a test email using saved SMTP settings."""
    data = request.json or {}
    test_email = (data.get('email') or '').strip()
    if not test_email or not is_valid_email(test_email):
        return jsonify({'error': 'Valid test email is required'}), 400

    test_url = f"{get_base_url()}/login"
    sent, error = send_password_reset_email(test_email, test_url)
    if not sent:
        log_audit(session.get('username'), 'MAIL_TEST_FAILED', error or 'Unknown mail error', 'failed')
        return jsonify({'error': error or 'Mail test failed'}), 500

    log_audit(session.get('username'), 'MAIL_TEST_SENT', f'Sent test email to: {test_email}', 'success')
    return jsonify({'success': True, 'message': 'Test email sent successfully'})

@app.route('/api/admin/users/<username>/delete', methods=['DELETE'])
@require_login
@require_role('admin')
def delete_user(username):
    """Delete user (admin only)"""
    if username == 'admin':
        return jsonify({'error': 'Cannot delete admin user'}), 400
    
    if username == session.get('username'):
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    if username not in users_db:
        return jsonify({'error': 'User not found'}), 404
    
    del users_db[username]
    log_audit(session.get('username'), 'USER_DELETED', f'Deleted user: {username}', 'success')
    save_runtime_config()
    
    return jsonify({'success': True, 'message': f'User {username} has been deleted'})

# --- AUDIT LOG ROUTES ---

@app.route('/api/admin/audit-logs', methods=['GET'])
@require_login
@require_role('admin')
def get_audit_logs():
    """Get audit logs (admin only)"""
    limit = request.args.get('limit', 100, type=int)
    return jsonify(audit_logs[:limit])

# --- DASHBOARD & MONITORING ROUTES ---

@app.route('/api/dashboard')
@require_login
def dashboard_api():
    """Get dashboard data"""
    user_role = session.get('user_role')
    username = session.get('username')
    current_user = users_db.get(username, {})
    user_full_name = current_user.get('full_name', '')

    if user_role == 'engineer' and user_full_name:
        visible = {k: v for k, v in ISP_CONFIG.items() if v.get('engineer') == user_full_name}
    else:
        visible = ISP_CONFIG

    sites_list = [{**v, **status_cache[k]} for k, v in visible.items()]
    return jsonify({
        'user': username,
        'full_name': current_user.get('full_name', username),
        'role': user_role,
        'summary': {
            'online': sum(1 for k in visible if status_cache[k]['status'] == 'online'),
            'offline': sum(1 for k in visible if status_cache[k]['status'] == 'offline')
        },
        'sites': sites_list
    })

@app.route('/api/sites')
@require_login
def get_all_sites():
    """Get all monitored sites"""
    user_role = session.get('user_role')
    username = session.get('username')
    current_user = users_db.get(username, {})
    user_full_name = current_user.get('full_name', '')

    if user_role == 'engineer' and user_full_name:
        visible = {k: v for k, v in ISP_CONFIG.items() if v.get('engineer') == user_full_name}
    else:
        visible = ISP_CONFIG

    sites_list = [{'site_id': k, **v, **status_cache[k]} for k, v in visible.items()]
    return jsonify({'total': len(sites_list), 'sites': sites_list})

@app.route('/api/zones')
@require_login
def get_zones():
    """Get all zones/regions"""
    zones_data = []
    for zone_name, zone_info in ZONES.items():
        zone_sites = [s for s in ISP_CONFIG.values() if s['region'] == zone_name]
        online_count = sum(1 for k, v in ISP_CONFIG.items() if v['region'] == zone_name and status_cache[k]['status'] == 'online')
        offline_count = sum(1 for k, v in ISP_CONFIG.items() if v['region'] == zone_name and status_cache[k]['status'] == 'offline')
        
        zones_data.append({
            'name': zone_name,
            'code': zone_info['region_code'],
            'description': zone_info['description'],
            'manager': zone_info['manager'],
            'color': zone_info['color'],
            'total_sites': len(zone_sites),
            'online': online_count,
            'offline': offline_count
        })
    return jsonify(zones_data)

@app.route('/api/zones', methods=['POST'])
@require_login
@require_role('admin')
def create_zone():
    """Create a new zone/region."""
    data = request.json or {}
    zone_name = (data.get('name') or '').strip()
    if not zone_name:
        return jsonify({'error': 'Zone name is required'}), 400
    if zone_name in ZONES:
        return jsonify({'error': 'Zone already exists'}), 400

    ZONES[zone_name] = {
        'region_code': (data.get('region_code') or zone_name[:2].upper()).strip(),
        'description': (data.get('description') or '').strip(),
        'manager': (data.get('manager') or '').strip(),
        'color': (data.get('color') or '#00e676').strip()
    }
    log_audit(session.get('username'), 'CREATE_ZONE', f'Created zone: {zone_name}')
    save_runtime_config()
    return jsonify({'success': True, 'message': 'Zone created successfully'})

@app.route('/api/zones/<zone_name>', methods=['PUT'])
@require_login
@require_role('admin')
def update_zone(zone_name):
    """Update a zone and move related site/engineer region names if renamed."""
    zone_name = zone_name.strip()
    if zone_name not in ZONES:
        return jsonify({'error': 'Zone not found'}), 404

    data = request.json or {}
    new_name = (data.get('name') or '').strip()
    if not new_name:
        return jsonify({'error': 'Zone name is required'}), 400
    if new_name != zone_name and new_name in ZONES:
        return jsonify({'error': 'Zone already exists'}), 400

    updated_info = {
        'region_code': (data.get('region_code') or new_name[:2].upper()).strip(),
        'description': (data.get('description') or '').strip(),
        'manager': (data.get('manager') or '').strip(),
        'color': (data.get('color') or '#00e676').strip()
    }

    if new_name != zone_name:
        ZONES[new_name] = updated_info
        del ZONES[zone_name]
        for site in ISP_CONFIG.values():
            if site.get('region') == zone_name:
                site['region'] = new_name
        for engineer in ENGINEERS.values():
            if engineer.get('region') == zone_name:
                engineer['region'] = new_name
        for future_site in future_sites_list:
            if future_site.get('region') == zone_name:
                future_site['region'] = new_name
    else:
        ZONES[zone_name] = updated_info

    log_audit(session.get('username'), 'UPDATE_ZONE', f'Updated zone: {zone_name} -> {new_name}')
    save_runtime_config()
    save_future_sites_to_file()
    return jsonify({'success': True, 'message': 'Zone updated successfully'})

@app.route('/api/engineers')
@require_login
def get_engineers():
    """Get all engineers"""
    engineers_data = []
    for eng_name, eng_info in ENGINEERS.items():
        assigned_sites = [k for k, v in ISP_CONFIG.items() if v['engineer'] == eng_name]
        online_sites = sum(1 for k in assigned_sites if status_cache[k]['status'] == 'online')
        offline_sites = sum(1 for k in assigned_sites if status_cache[k]['status'] == 'offline')
        
        engineers_data.append({
            'name': eng_name,
            'email': eng_info['email'],
            'phone': eng_info['phone'],
            'team_number': eng_info.get('team_number', ''),
            'region': eng_info['region'],
            'status': eng_info['status'],
            'assigned_sites': len(assigned_sites),
            'sites_online': online_sites,
            'sites_offline': offline_sites,
            'sites': assigned_sites
        })
    return jsonify(engineers_data)

@app.route('/api/engineers', methods=['POST'])
@require_login
@require_role('admin')
def create_engineer():
    """Create a new engineer for assignment to future/current sites."""
    data = request.json or {}
    name = (data.get('name') or '').strip()
    region = (data.get('region') or '').strip()

    if not name:
        return jsonify({'error': 'Engineer name is required'}), 400
    if not region:
        return jsonify({'error': 'Region is required'}), 400
    if name in ENGINEERS:
        return jsonify({'error': 'Engineer already exists'}), 400

    ENGINEERS[name] = {
        'email': (data.get('email') or '').strip(),
        'phone': (data.get('phone') or '').strip(),
        'team_number': (data.get('team_number') or '').strip(),
        'region': region,
        'status': (data.get('status') or 'active').strip()
    }

    log_audit(session.get('username'), 'CREATE_ENGINEER', f'Created engineer: {name}')
    save_runtime_config()
    return jsonify({'success': True, 'message': 'Engineer created successfully'})

@app.route('/api/engineers/<engineer_name>', methods=['PUT'])
@require_login
@require_role('admin')
def update_engineer(engineer_name):
    """Update engineer details and move assigned sites if the name changes."""
    engineer_name = engineer_name.strip()
    if engineer_name not in ENGINEERS:
        return jsonify({'error': 'Engineer not found'}), 404

    data = request.json or {}
    new_name = (data.get('name') or '').strip()
    new_region = (data.get('region') or '').strip()

    if not new_name:
        return jsonify({'error': 'Engineer name is required'}), 400
    if not new_region:
        return jsonify({'error': 'Region is required'}), 400
    if new_name != engineer_name and new_name in ENGINEERS:
        return jsonify({'error': 'Engineer name already exists'}), 400

    updated_info = {
        'email': (data.get('email') or '').strip(),
        'phone': (data.get('phone') or '').strip(),
        'team_number': (data.get('team_number') or '').strip(),
        'region': new_region,
        'status': (data.get('status') or 'active').strip()
    }

    if new_name != engineer_name:
        ENGINEERS[new_name] = updated_info
        del ENGINEERS[engineer_name]
        for site in ISP_CONFIG.values():
            if site.get('engineer') == engineer_name:
                site['engineer'] = new_name
        for future_site in future_sites_list:
            if future_site.get('engineer') == engineer_name:
                future_site['engineer'] = new_name
    else:
        ENGINEERS[engineer_name] = updated_info

    log_audit(session.get('username'), 'UPDATE_ENGINEER', f'Updated engineer: {engineer_name} -> {new_name}')
    save_runtime_config()
    save_future_sites_to_file()
    return jsonify({'success': True, 'message': 'Engineer updated successfully', 'engineer': {'name': new_name, **updated_info}})

@app.route('/api/reports')
@require_login
def get_reports():
    """Get incident reports"""
    return jsonify(downtime_logs)

@app.route('/api/reports/download')
@require_login
@require_role('engineer')
def download_reports():
    """Download reports as CSV"""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'Site', 'Region', 'ISP Provider', 'Engineer', 'Status'])
    
    for log in downtime_logs:
        writer.writerow([log['timestamp'], log['site'], log['region'], log['isp'], log['engineer'], log['status'].upper()])
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'incident_reports_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )

@app.route('/api/reports/download-json')
@require_login
@require_role('engineer')
def download_reports_json():
    """Download reports as JSON"""
    output = io.BytesIO(json.dumps(downtime_logs, indent=2).encode())
    output.seek(0)
    return send_file(
        output,
        mimetype='application/json',
        as_attachment=True,
        download_name=f'incident_reports_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    )

@app.route('/api/sites/by-zone/<zone_name>')
@require_login
def get_sites_by_zone(zone_name):
    """Get sites in a specific zone"""
    sites_list = []
    for k, v in ISP_CONFIG.items():
        if v['region'] == zone_name:
            sites_list.append({'site_id': k, **v, **status_cache[k]})
    return jsonify({'zone': zone_name, 'sites': sites_list})

@app.route('/api/engineer/<engineer_name>/sites')
@require_login
def get_engineer_sites(engineer_name):
    """Get sites assigned to an engineer"""
    sites_list = []
    for k, v in ISP_CONFIG.items():
        if v['engineer'] == engineer_name:
            sites_list.append({'site_id': k, **v, **status_cache[k]})
    return jsonify({'engineer': engineer_name, 'sites': sites_list})

def add_downtime_interval(start, end, range_start, range_end, daily_minutes, site_minutes, site_name):
    """Add a downtime interval to daily and per-site totals."""
    interval_start = max(start, range_start)
    interval_end = min(end, range_end)
    if interval_end <= interval_start:
        return

    site_minutes[site_name] = site_minutes.get(site_name, 0) + (interval_end - interval_start).total_seconds() / 60
    cursor = interval_start
    while cursor < interval_end:
        next_day = datetime.combine(cursor.date() + timedelta(days=1), datetime.min.time())
        segment_end = min(next_day, interval_end)
        day_key = cursor.strftime('%Y-%m-%d')
        if day_key in daily_minutes:
            daily_minutes[day_key] += (segment_end - cursor).total_seconds() / 60
        cursor = segment_end

@app.route('/api/statistics')
@require_login
def get_statistics():
    """Get network statistics"""
    total_sites = len(ISP_CONFIG)
    online_sites = sum(1 for s in status_cache.values() if s['status'] == 'online')
    offline_sites = sum(1 for s in status_cache.values() if s['status'] == 'offline')
    uptime_percentage = (online_sites / total_sites * 100) if total_sites > 0 else 0
    
    return jsonify({
        'total_sites': total_sites,
        'online_sites': online_sites,
        'offline_sites': offline_sites,
        'uptime_percentage': round(uptime_percentage, 2),
        'total_engineers': len(ENGINEERS),
        'total_zones': len(ZONES),
        'total_incidents': len(downtime_logs),
        'future_sites_pending': len([s for s in future_sites_list if s.get('status') == 'planned'])
    })

@app.route('/api/dashboard/charts')
@require_login
def get_dashboard_charts():
    """Get chart-ready network health and downtime data."""
    now = datetime.now()
    day_labels = [(now - timedelta(days=offset)).strftime('%Y-%m-%d') for offset in range(6, -1, -1)]
    downtime_minutes = {day: 0 for day in day_labels}
    offline_incidents = {day: 0 for day in day_labels}

    events_by_site = {}
    for event in reversed(downtime_logs):
        try:
            event_time = datetime.strptime(event['timestamp'], '%Y-%m-%d %H:%M:%S')
        except (KeyError, TypeError, ValueError):
            continue
        events_by_site.setdefault(event.get('site', 'Unknown Site'), []).append((event_time, event.get('status')))
        day_key = event_time.strftime('%Y-%m-%d')
        if event.get('status') == 'offline' and day_key in offline_incidents:
            offline_incidents[day_key] += 1

    downtime_by_site = {}
    range_start = datetime.strptime(day_labels[0], '%Y-%m-%d')
    range_end = now
    for site_name, events in events_by_site.items():
        offline_start = None
        for event_time, status in events:
            if status == 'offline':
                offline_start = event_time
            elif status == 'online' and offline_start:
                add_downtime_interval(offline_start, event_time, range_start, range_end, downtime_minutes, downtime_by_site, site_name)
                offline_start = None
        if offline_start:
            add_downtime_interval(offline_start, now, range_start, range_end, downtime_minutes, downtime_by_site, site_name)

    zone_health = []
    for zone_name in ZONES:
        zone_site_ids = [key for key, site in ISP_CONFIG.items() if site.get('region') == zone_name]
        zone_health.append({
            'zone': zone_name,
            'online': sum(1 for key in zone_site_ids if status_cache.get(key, {}).get('status') == 'online'),
            'offline': sum(1 for key in zone_site_ids if status_cache.get(key, {}).get('status') == 'offline'),
            'checking': sum(1 for key in zone_site_ids if status_cache.get(key, {}).get('status') == 'checking')
        })

    top_downtime_sites = sorted(downtime_by_site.items(), key=lambda item: item[1], reverse=True)[:5]
    return jsonify({
        'status': {
            'online': sum(1 for status in status_cache.values() if status.get('status') == 'online'),
            'offline': sum(1 for status in status_cache.values() if status.get('status') == 'offline'),
            'checking': sum(1 for status in status_cache.values() if status.get('status') == 'checking')
        },
        'zone_health': zone_health,
        'downtime': {
            'labels': day_labels,
            'minutes': [round(downtime_minutes[day], 1) for day in day_labels],
            'incidents': [offline_incidents[day] for day in day_labels]
        },
        'top_downtime_sites': {
            'labels': [item[0] for item in top_downtime_sites],
            'minutes': [round(item[1], 1) for item in top_downtime_sites]
        }
    })

# --- PAGE ROUTES ---

@app.route('/')
def index():
    """Serve dashboard"""
    if not session.get('loggedIn') or not check_session_timeout():
        return redirect('/login')
    return send_from_directory('.', 'dashboard.html')

@app.route('/login')
def login_page():
    """Serve login page"""
    if session.get('loggedIn') and check_session_timeout():
        return redirect('/')
    return send_from_directory('.', 'login.html')

@app.route('/reset-password')
def reset_password_page():
    """Serve password reset page"""
    return send_from_directory('.', 'reset-password.html')

# ============================================
# KMV ADD-ON FEATURES
# Logo + Filter + Add Site (added after main section)
# ============================================

from werkzeug.utils import secure_filename

UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
LOGO_METADATA_FILE = os.path.join(UPLOAD_FOLDER, 'company_logo.json')
DATA_DIR = os.path.join(BASE_DIR, 'data')
RUNTIME_CONFIG_FILE = os.path.join(DATA_DIR, 'portal_config.json')
MAIL_SETTINGS_FILE = os.path.join(DATA_DIR, 'mail_settings.json')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

company_logo_info = {
    'filename': None,
    'upload_date': None
}

def get_database_url():
    return os.environ.get(
        'DATABASE_URL',
        'postgresql://kmv_admin:kmv_password@db:5432/kmv_network_db'
    )

def get_db_connection():
    if psycopg2 is None:
        return None
    try:
        return psycopg2.connect(get_database_url(), connect_timeout=3)
    except Exception as e:
        print(f"Database unavailable, using local JSON fallback: {e}")
        return None

def ensure_portal_state_table():
    conn = get_db_connection()
    if not conn:
        return False
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS portal_state (
                        state_key VARCHAR(64) PRIMARY KEY,
                        state_value JSONB NOT NULL,
                        updated_at TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
        return True
    except Exception as e:
        print(f"Could not initialize portal_state table: {e}")
        return False
    finally:
        conn.close()

def save_state_to_db(state_key, state_value):
    conn = get_db_connection()
    if not conn:
        return False
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO portal_state (state_key, state_value, updated_at)
                    VALUES (%s, %s::jsonb, NOW())
                    ON CONFLICT (state_key)
                    DO UPDATE SET state_value = EXCLUDED.state_value, updated_at = NOW()
                """, (state_key, json.dumps(state_value)))
        return True
    except Exception as e:
        print(f"Could not save {state_key} to database: {e}")
        return False
    finally:
        conn.close()

def load_state_from_db(state_key):
    conn = get_db_connection()
    if not conn:
        return None
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT state_value FROM portal_state WHERE state_key = %s", (state_key,))
            row = cur.fetchone()
            return row[0] if row else None
    except Exception as e:
        print(f"Could not load {state_key} from database: {e}")
        return None
    finally:
        conn.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def build_runtime_config():
    custom_sites = {
        key: value
        for key, value in ISP_CONFIG.items()
        if value.get('activated_from_future') or key.startswith('future_')
    }
    site_assignments = {
        key: {
            'name': value.get('name'),
            'ip': value.get('ip'),
            'isp': value.get('isp'),
            'region': value.get('region'),
            'engineer': value.get('engineer')
        }
        for key, value in ISP_CONFIG.items()
    }
    return {
        'users': users_db,
        'zones': ZONES,
        'engineers': ENGINEERS,
        'custom_sites': custom_sites,
        'site_assignments': site_assignments,
        'deleted_sites': sorted(DELETED_SITE_IDS)
    }

def apply_runtime_config(config):
    if not isinstance(config, dict):
        return

    saved_users = config.get('users')
    if isinstance(saved_users, dict):
        users_db.clear()
        users_db.update(saved_users)

    saved_zones = config.get('zones')
    if isinstance(saved_zones, dict):
        ZONES.clear()
        ZONES.update(saved_zones)

    saved_engineers = config.get('engineers')
    if isinstance(saved_engineers, dict):
        ENGINEERS.clear()
        ENGINEERS.update(saved_engineers)

    saved_custom_sites = config.get('custom_sites')
    if isinstance(saved_custom_sites, dict):
        for site_key, site_info in saved_custom_sites.items():
            if not isinstance(site_info, dict):
                continue
            if not all(site_info.get(field) for field in ('name', 'ip', 'region', 'isp')):
                continue

            ISP_CONFIG[site_key] = {
                'region': site_info.get('region'),
                'name': site_info.get('name'),
                'ip': site_info.get('ip'),
                'isp': site_info.get('isp'),
                'engineer': site_info.get('engineer') or 'Not Assigned',
                'activated_from_future': site_info.get('activated_from_future', True)
            }
            status_cache.setdefault(site_key, {'status': 'checking', 'latency': 0, 'ts': '--'})

    for site_key, assignment in config.get('site_assignments', {}).items():
        if site_key in ISP_CONFIG:
            if assignment.get('name'):
                ISP_CONFIG[site_key]['name'] = assignment['name']
            if assignment.get('ip'):
                ISP_CONFIG[site_key]['ip'] = assignment['ip']
            if assignment.get('isp'):
                ISP_CONFIG[site_key]['isp'] = assignment['isp']
            if assignment.get('region'):
                ISP_CONFIG[site_key]['region'] = assignment['region']
            if assignment.get('engineer'):
                ISP_CONFIG[site_key]['engineer'] = assignment['engineer']

    saved_deleted_sites = config.get('deleted_sites', [])
    if isinstance(saved_deleted_sites, list):
        DELETED_SITE_IDS.clear()
        DELETED_SITE_IDS.update(site_id for site_id in saved_deleted_sites if isinstance(site_id, str))
        for site_id in DELETED_SITE_IDS:
            ISP_CONFIG.pop(site_id, None)
            status_cache.pop(site_id, None)

def save_runtime_config():
    """Persist portal-managed names and user profile data to DB, with JSON fallback."""
    config = build_runtime_config()
    save_state_to_db('runtime_config', config)
    try:
        with open(RUNTIME_CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        print(f"Could not save portal config file: {e}")

def load_runtime_config():
    """Load portal-managed names and user profile data from DB first, then JSON."""
    try:
        ensure_portal_state_table()
        config = load_state_from_db('runtime_config')
        if config:
            apply_runtime_config(config)
            return

        if os.path.exists(RUNTIME_CONFIG_FILE):
            with open(RUNTIME_CONFIG_FILE, 'r') as f:
                config = json.load(f)
            apply_runtime_config(config)
            save_state_to_db('runtime_config', config)
        else:
            save_state_to_db('runtime_config', build_runtime_config())
    except Exception as e:
        print(f"Could not load portal config: {e}")

def save_company_logo_info():
    try:
        with open(LOGO_METADATA_FILE, 'w') as f:
            json.dump(company_logo_info, f, indent=2)
    except Exception as e:
        print(f"Could not save company logo metadata: {e}")

def load_company_logo_from_uploads():
    """Restore the uploaded company logo after app restart."""
    try:
        if os.path.exists(LOGO_METADATA_FILE):
            with open(LOGO_METADATA_FILE, 'r') as f:
                saved_info = json.load(f)
            saved_filename = saved_info.get('filename')
            if saved_filename and os.path.exists(os.path.join(UPLOAD_FOLDER, saved_filename)):
                company_logo_info['filename'] = saved_filename
                company_logo_info['upload_date'] = saved_info.get('upload_date')
                return

        logo_files = [
            f for f in os.listdir(UPLOAD_FOLDER)
            if (f.startswith('company_logo.') or f.startswith('kmv_logo_')) and allowed_file(f)
        ]
        if not logo_files:
            return

        latest_logo = max(
            logo_files,
            key=lambda f: os.path.getmtime(os.path.join(UPLOAD_FOLDER, f))
        )
        company_logo_info['filename'] = latest_logo
        company_logo_info['upload_date'] = datetime.fromtimestamp(
            os.path.getmtime(os.path.join(UPLOAD_FOLDER, latest_logo))
        ).isoformat()
        save_company_logo_info()
    except Exception as e:
        print(f"Could not load company logo: {e}")

# ==========================================
# LOGO ENDPOINTS
# ==========================================

@app.route('/api/company/logo', methods=['POST'])
@require_login
def upload_company_logo():
    """Upload company logo"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed (PNG, JPG, GIF, WebP only)'}), 400
    
    try:
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = secure_filename(f"company_logo.{ext}")
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        for old_logo in os.listdir(UPLOAD_FOLDER):
            if old_logo.startswith('company_logo.') and old_logo != filename:
                try:
                    os.remove(os.path.join(UPLOAD_FOLDER, old_logo))
                except:
                    pass
        file.save(filepath)
        
        company_logo_info['filename'] = filename
        company_logo_info['upload_date'] = datetime.now().isoformat()
        save_company_logo_info()
        
        return jsonify({
            'success': True,
            'message': 'Logo uploaded successfully',
            'filename': filename,
            'logo_url': '/api/company/logo'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/company/logo', methods=['GET'])
def get_company_logo():
    """Get company logo image"""
    if company_logo_info['filename']:
        try:
            return send_from_directory(UPLOAD_FOLDER, company_logo_info['filename'])
        except:
            pass
    return jsonify({'error': 'No logo uploaded'}), 404

@app.route('/api/company/info')
def get_company_info():
    """Get company logo metadata"""
    return jsonify({
        'has_logo': company_logo_info['filename'] is not None,
        'filename': company_logo_info['filename'],
        'logo_url': '/api/company/logo' if company_logo_info['filename'] else None,
        'upload_date': company_logo_info['upload_date']
    })

# ==========================================
# SITE MANAGEMENT ENDPOINTS
# ==========================================

sites_list = []
next_site_id = 1

def make_site_key(name, ip):
    base = re.sub(r'[^a-z0-9]+', '_', (name or 'site').lower()).strip('_') or 'site'
    ip_suffix = re.sub(r'[^0-9]+', '_', (ip or '')).strip('_')
    site_key = f"{base}_{ip_suffix}"[:64].strip('_')
    if not site_key:
        site_key = f"site_{int(time.time())}"

    original_key = site_key
    counter = 2
    while site_key in ISP_CONFIG:
        suffix = f"_{counter}"
        site_key = f"{original_key[:64 - len(suffix)]}{suffix}"
        counter += 1
    return site_key

@app.route('/api/sites/add', methods=['POST'])
@require_login
@require_role('admin')
def add_new_site():
    """Add a new site to monitor"""
    global next_site_id
    data = request.json or {}
    
    required = ['name', 'isp', 'ip']
    if not all(field in data for field in required):
        return jsonify({'error': 'Missing required fields: name, isp, ip'}), 400
    
    try:
        site_key = make_site_key(data.get('name'), data.get('ip'))
        DELETED_SITE_IDS.discard(site_key)
        region = (data.get('region') or data.get('zone') or 'Unassigned').strip()
        engineer = (data.get('engineer') or data.get('manager') or 'Not Assigned').strip()

        ISP_CONFIG[site_key] = {
            'region': region,
            'name': data.get('name').strip(),
            'ip': data.get('ip').strip(),
            'isp': data.get('isp').strip(),
            'engineer': engineer,
            'activated_from_future': True
        }
        status_cache[site_key] = {'status': 'checking', 'latency': 0, 'ts': '--'}

        new_site = {
            'id': next_site_id,
            'site_id': site_key,
            'name': data.get('name'),
            'location': data.get('location') or data.get('name'),
            'zone': region,
            'isp': data.get('isp'),
            'ip': data.get('ip'),
            'manager': engineer,
            'status': 'checking',
            'response_time': None,
            'added_date': datetime.now().isoformat()
        }
        
        sites_list.append(new_site)
        next_site_id += 1
        
        try:
            with open(os.path.join(BASE_DIR, 'sites_data.json'), 'w') as f:
                json.dump(sites_list, f, indent=2)
        except:
            pass
        save_runtime_config()
        log_audit(session.get('username'), 'ADD_MONITORING_SITE', f'Added monitoring site: {new_site["name"]}')
        
        return jsonify({'success': True, 'message': 'Site added successfully', 'site': new_site}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sites/<site_id>', methods=['PUT'])
@require_login
@require_role('admin')
def update_monitoring_site(site_id):
    """Update an existing monitored site."""
    if site_id not in ISP_CONFIG:
        return jsonify({'error': 'Site not found'}), 404

    data = request.json or {}
    name = (data.get('name') or '').strip()
    ip = (data.get('ip') or '').strip()
    isp = (data.get('isp') or '').strip()
    region = (data.get('region') or data.get('zone') or '').strip()
    engineer = (data.get('engineer') or data.get('manager') or 'Not Assigned').strip()

    if not name or not ip or not isp or not region:
        return jsonify({'error': 'Site name, IP address, ISP, and zone are required'}), 400

    site = ISP_CONFIG[site_id]
    old_ip = site.get('ip')
    site.update({
        'name': name,
        'ip': ip,
        'isp': isp,
        'region': region,
        'engineer': engineer
    })

    for dynamic_site in sites_list:
        if dynamic_site.get('site_id') == site_id:
            dynamic_site.update({
                'name': name,
                'location': (data.get('location') or name).strip(),
                'zone': region,
                'isp': isp,
                'ip': ip,
                'manager': engineer
            })
            break

    if old_ip != ip:
        status_cache[site_id] = {'status': 'checking', 'latency': 0, 'ts': '--'}

    save_runtime_config()
    log_audit(session.get('username'), 'UPDATE_MONITORING_SITE', f'Updated monitoring site: {name}')
    return jsonify({'success': True, 'message': 'Site updated successfully', 'site': {'site_id': site_id, **site}})

@app.route('/api/sites/<site_id>', methods=['DELETE'])
@require_login
@require_role('admin')
def delete_monitoring_site(site_id):
    """Remove a closed site from monitoring."""
    global sites_list
    site = ISP_CONFIG.get(site_id)
    if not site:
        return jsonify({'error': 'Site not found'}), 404

    site_name = site.get('name', site_id)
    ISP_CONFIG.pop(site_id, None)
    status_cache.pop(site_id, None)
    DELETED_SITE_IDS.add(site_id)
    sites_list = [dynamic_site for dynamic_site in sites_list if dynamic_site.get('site_id') != site_id]

    try:
        with open(os.path.join(BASE_DIR, 'sites_data.json'), 'w') as f:
            json.dump(sites_list, f, indent=2)
    except Exception as e:
        print(f"Could not save sites data file: {e}")

    save_runtime_config()
    log_audit(session.get('username'), 'DELETE_MONITORING_SITE', f'Deleted monitoring site: {site_name}')
    return jsonify({'success': True, 'message': 'Site deleted successfully'})

@app.route('/api/sites/list', methods=['GET'])
@require_login
def get_dynamic_sites():
    """Get all dynamically added sites"""
    return jsonify(sites_list)

@app.route('/api/sites/filter/online')
@require_login
def get_online_sites():
    """Get only online sites"""
    return jsonify([s for s in sites_list if s.get('status') == 'online'])

@app.route('/api/sites/filter/offline')
@require_login
def get_offline_sites():
    """Get only offline sites"""
    return jsonify([s for s in sites_list if s.get('status') == 'offline'])

@app.route('/api/stats/summary')
@require_login
def get_stats_summary():
    """Get statistics summary"""
    total = len(sites_list)
    online = len([s for s in sites_list if s.get('status') == 'online'])
    offline = total - online
    return jsonify({
        'total_sites': total,
        'online_sites': online,
        'offline_sites': offline,
        'uptime_percentage': round((online / total * 100), 2) if total > 0 else 0,
        'timestamp': datetime.now().isoformat()
    })

# ==========================================
# FUTURE SITES MANAGEMENT
# ==========================================

future_sites_list = []
next_future_site_id = 1
FUTURE_SITE_FIELDS = [
    'name', 'site_code', 'location', 'address', 'ip', 'gateway', 'subnet',
    'isp', 'backup_isp', 'bandwidth', 'circuit_id', 'engineer',
    'contact_name', 'contact_phone', 'contact_email', 'priority', 'region',
    'expected_date', 'notes'
]

def clean_future_site_value(value):
    if isinstance(value, str):
        value = value.strip()
    return value or None

def build_future_site_payload(data):
    return {
        field: clean_future_site_value(data.get(field))
        for field in FUTURE_SITE_FIELDS
    }

def save_future_sites_to_file():
    try:
        with open(os.path.join(BASE_DIR, 'future_sites_data.json'), 'w') as f:
            json.dump(future_sites_list, f, indent=2)
    except Exception as e:
        print(f"Could not save future sites: {e}")

def validate_future_site_payload(site):
    required_fields = {
        'ip': 'IP address',
        'location': 'Location',
        'region': 'Zone'
    }

    for field, label in required_fields.items():
        if not site.get(field):
            return f'{label} is required'
    return None

@app.route('/api/sites/future', methods=['GET'])
@require_login
@require_role('engineer')
def get_future_sites():
    """Get all future sites (planned for activation)"""
    return jsonify(future_sites_list)

@app.route('/api/sites/future', methods=['POST'])
@require_login
@require_role('engineer')
def add_future_site():
    """Add a new future site (not yet active)"""
    global next_future_site_id
    data = request.json or {}
    site_payload = build_future_site_payload(data)
    
    validation_error = validate_future_site_payload(site_payload)
    if validation_error:
        return jsonify({'error': validation_error}), 400
    site_payload['name'] = site_payload.get('name') or site_payload.get('location')
    
    try:
        future_site = {
            'id': f'future_{next_future_site_id}',
            **site_payload,
            'created_by': session.get('username'),
            'created_at': datetime.now().isoformat(),
            'status': 'planned'
        }
        
        future_sites_list.append(future_site)
        next_future_site_id += 1
        
        # Audit log
        log_audit(session.get('username'), 'ADD_FUTURE_SITE', f'Added future site: {future_site["name"]}')
        
        try:
            with open(os.path.join(BASE_DIR, 'future_sites_data.json'), 'w') as f:
                json.dump(future_sites_list, f, indent=2)
        except:
            pass
        
        return jsonify({
            'success': True,
            'message': 'Future site added successfully',
            'site': future_site
        }), 201
    except Exception as e:
        log_audit(session.get('username'), 'ADD_FUTURE_SITE', f'Error: {str(e)}', 'failed')
        return jsonify({'error': str(e)}), 500

@app.route('/api/sites/future/<site_id>', methods=['GET'])
@require_login
@require_role('engineer')
def get_future_site(site_id):
    """Get a specific future site"""
    site = next((s for s in future_sites_list if s['id'] == site_id), None)
    if not site:
        return jsonify({'error': 'Future site not found'}), 404
    return jsonify(site)

@app.route('/api/sites/future/<site_id>', methods=['PUT'])
@require_login
@require_role('engineer')
def update_future_site(site_id):
    """Update a future site"""
    site = next((s for s in future_sites_list if s['id'] == site_id), None)
    if not site:
        return jsonify({'error': 'Future site not found'}), 404
    
    data = request.json or {}
    try:
        for field, value in build_future_site_payload(data).items():
            if field in data:
                site[field] = value

        validation_error = validate_future_site_payload(site)
        if validation_error:
            return jsonify({'error': validation_error}), 400
        site['name'] = site.get('name') or site.get('location')
        
        site['updated_at'] = datetime.now().isoformat()
        site['updated_by'] = session.get('username')
        
        log_audit(session.get('username'), 'UPDATE_FUTURE_SITE', f'Updated future site: {site["name"]}')
        
        try:
            with open(os.path.join(BASE_DIR, 'future_sites_data.json'), 'w') as f:
                json.dump(future_sites_list, f, indent=2)
        except:
            pass
        
        return jsonify({
            'success': True,
            'message': 'Future site updated successfully',
            'site': site
        })
    except Exception as e:
        log_audit(session.get('username'), 'UPDATE_FUTURE_SITE', f'Error: {str(e)}', 'failed')
        return jsonify({'error': str(e)}), 500

@app.route('/api/sites/future/<site_id>', methods=['DELETE'])
@require_login
@require_role('engineer')
def delete_future_site(site_id):
    """Delete a future site"""
    global future_sites_list
    site = next((s for s in future_sites_list if s['id'] == site_id), None)
    if not site:
        return jsonify({'error': 'Future site not found'}), 404
    
    try:
        site_name = site['name']
        future_sites_list = [s for s in future_sites_list if s['id'] != site_id]
        
        log_audit(session.get('username'), 'DELETE_FUTURE_SITE', f'Deleted future site: {site_name}')
        
        try:
            with open(os.path.join(BASE_DIR, 'future_sites_data.json'), 'w') as f:
                json.dump(future_sites_list, f, indent=2)
        except:
            pass
        
        return jsonify({'success': True, 'message': 'Future site deleted successfully'})
    except Exception as e:
        log_audit(session.get('username'), 'DELETE_FUTURE_SITE', f'Error: {str(e)}', 'failed')
        return jsonify({'error': str(e)}), 500

@app.route('/api/sites/future/<site_id>/activate', methods=['POST'])
@require_login
@require_role('admin')
def activate_future_site(site_id):
    """Activate a future site and add it to monitoring"""
    site = next((s for s in future_sites_list if s['id'] == site_id), None)
    if not site:
        return jsonify({'error': 'Future site not found'}), 404

    if not site.get('ip'):
        return jsonify({'error': 'Primary IP address is required before activation'}), 400
    
    try:
        assigned_engineer = site.get('engineer') or 'Not Assigned'
        # Create new monitoring site from future site
        new_monitoring_site = {
            'site_id': site['id'],
            'name': site['name'],
            'ip': site['ip'],
            'isp': site['isp'],
            'region': site['region'],
            'engineer': assigned_engineer,
            'status': 'checking',
            'latency': 0,
            'ts': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'activated_from_future': True,
            'activated_at': datetime.now().isoformat(),
            'activated_by': session.get('username')
        }
        
        # Add to ISP_CONFIG for monitoring
        ISP_CONFIG[site_id] = {
            'region': site['region'],
            'name': site['name'],
            'ip': site['ip'],
            'isp': site.get('isp') or site.get('backup_isp') or 'Unknown',
            'engineer': assigned_engineer,
            'activated_from_future': True
        }
        
        # Initialize status cache
        status_cache[site_id] = {'status': 'checking', 'latency': 0, 'ts': '--'}
        
        # Update future site status
        site['status'] = 'activated'
        site['activated_at'] = datetime.now().isoformat()
        site['activated_by'] = session.get('username')
        
        log_audit(session.get('username'), 'ACTIVATE_FUTURE_SITE', f'Activated future site: {site["name"]}')
        
        try:
            with open(os.path.join(BASE_DIR, 'future_sites_data.json'), 'w') as f:
                json.dump(future_sites_list, f, indent=2)
        except:
            pass
        save_runtime_config()
        
        return jsonify({
            'success': True,
            'message': f'Future site "{site["name"]}" activated and added to monitoring',
            'site': new_monitoring_site
        })
    except Exception as e:
        log_audit(session.get('username'), 'ACTIVATE_FUTURE_SITE', f'Error: {str(e)}', 'failed')
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats/future-sites')
@require_login
def get_future_sites_stats():
    """Get statistics about future sites"""
    total_future = len(future_sites_list)
    planned = len([s for s in future_sites_list if s.get('status') == 'planned'])
    activated = len([s for s in future_sites_list if s.get('status') == 'activated'])
    
    return jsonify({
        'total_future_sites': total_future,
        'planned_sites': planned,
        'activated_sites': activated,
        'timestamp': datetime.now().isoformat()
    })

def load_future_sites_from_file():
    """Load previously added future sites from JSON file"""
    global future_sites_list, next_future_site_id
    try:
        future_path = os.path.join(BASE_DIR, 'future_sites_data.json')
        if os.path.exists(future_path):
            with open(future_path, 'r') as f:
                future_sites_list = json.load(f)
                if future_sites_list:
                    for site in future_sites_list:
                        site.setdefault('status', 'planned')
                    # Extract the highest ID number
                    future_ids = [
                        int(s['id'].split('_')[1]) 
                        for s in future_sites_list 
                        if s.get('id', '').startswith('future_') and s['id'].split('_')[1].isdigit()
                    ]
                    next_future_site_id = (max(future_ids) + 1) if future_ids else 1
    except Exception as e:
        print(f"Could not load future sites from file: {e}")

def load_sites_from_file():
    """Load previously added sites from JSON file"""
    global sites_list, next_site_id
    try:
        sites_path = os.path.join(BASE_DIR, 'sites_data.json')
        if os.path.exists(sites_path):
            with open(sites_path, 'r') as f:
                sites_list = json.load(f)
                if sites_list:
                    next_site_id = max([s['id'] for s in sites_list]) + 1
    except Exception as e:
        print(f"Could not load sites from file: {e}")

# Load any previously saved sites on startup
load_runtime_config()
load_company_logo_from_uploads()
load_sites_from_file()
load_future_sites_from_file()

if __name__ == '__main__':
    threading.Thread(target=ping_worker, daemon=True).start()
    # The reloader runs the ping worker twice (duplicate alert mails); turn it off in containers.
    use_reloader = os.environ.get('FLASK_USE_RELOADER', 'true').lower() == 'true'
    app.run(host='0.0.0.0', port=3000, debug=False, use_reloader=use_reloader, reloader_type='stat')
