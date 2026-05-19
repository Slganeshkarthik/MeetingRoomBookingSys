from flask import Flask, request, jsonify, render_template, redirect, url_for, session, send_from_directory, abort
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect
import mysql.connector
import os
import sys
import datetime
from functools import wraps # decorators 
import atexit # db
import importlib # dynamic lib integration
import smtplib # smtp
import uuid # unquie id
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import secrets

try:
    flask_mail_module = importlib.import_module('flask_mail')
    Mail = getattr(flask_mail_module, 'Mail')
    Message = getattr(flask_mail_module, 'Message')
except Exception:
    Mail = None
    Message = None

try:
    scheduler_module = importlib.import_module('apscheduler.schedulers.background')
    BackgroundScheduler = getattr(scheduler_module, 'BackgroundScheduler')
except Exception:
    BackgroundScheduler = None

# Ensure sibling folders (e.g., dataBase/) are importable when app.py is run directly.
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

def load_dotenv_file(dotenv_path):
    if not os.path.exists(dotenv_path):
        return

    with open(dotenv_path, 'r', encoding='utf-8') as env_file:
        for raw_line in env_file:
            line = raw_line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue

            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")

            # Do not override already exported environment variables.
            if key and key not in os.environ:
                os.environ[key] = value


load_dotenv_file(os.path.join(PROJECT_ROOT, '.env'))

from dataBase.db_init import (
    init_db,
    get_user_details,
    update_user_details,
    create_signup_notification,
    create_booking_notification,
    generate_booking_id,
    get_pending_notifications_for_role,
    update_notification_stage,
    get_connection,
    create_booking_request,
    get_requests_for_user,
    update_booking_document,
    take_approval_action,
    get_waiting_count,
    suggest_alternative_slot,
    accept_suggested_slot,
    expire_stale_requests,
    process_one_click_approval,
    upsert_hall,
    list_halls,
    delete_hall,
    override_booking_status,
    get_admin_analytics,
    get_approver_analytics,
    parse_datetime,
    get_config,
    get_all_config,
    set_config,
    create_admin_alert,
    get_recent_admin_alerts,
    mark_admin_alerts_as_read,
    resolve_buffer_minutes,
)

TEMPLATE_DIR = os.path.join(PROJECT_ROOT, 'frontend', 'templates')
STATIC_DIR = os.path.join(PROJECT_ROOT, 'frontend', 'static')

app = Flask(
    __name__,
    template_folder=TEMPLATE_DIR,
    static_folder=STATIC_DIR,
    static_url_path='/static',
)

app.secret_key = secrets.token_hex(32) # Better secret key handling
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Set max content length to 16MB
app.config['MAX_COOKIE_SIZE'] = 4096  # Set max cookie size to 4KB
app.config['WTF_CSRF_TIME_LIMIT'] = 3600
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', '587'))
app.config['MAIL_USE_TLS'] = str(os.environ.get('MAIL_USE_TLS', 'true')).lower() == 'true'
app.config['MAIL_USE_SSL'] = str(os.environ.get('MAIL_USE_SSL', 'false')).lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])
app.config['APP_BASE_URL'] = os.environ.get('APP_BASE_URL', 'http://localhost:5000')

# Allow overriding the OTP/admin email via environment for quick dev changes.
# If ADMIN_OTP_EMAIL is set in the environment (or in .env), use it as the
# default sender and as the preferred admin OTP recipient.
if os.environ.get('ADMIN_OTP_EMAIL'):
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('ADMIN_OTP_EMAIL')



import threading

CORS(app, supports_credentials=True)
csrf = CSRFProtect(app)
mail = Mail(app) if Mail else None

def send_async_email(app_for_thread, message):
    with app_for_thread.app_context():
        try:
            if mail:
                mail.send(message)
        except Exception as e:
            print(f"Async email send failed: {e}")

def send_email_in_thread(message):
    if not mail:
        return
    real_app = app._get_current_object() if hasattr(app, '_get_current_object') else app
    thr = threading.Thread(target=send_async_email, args=(real_app, message))
    thr.start()
scheduler = BackgroundScheduler(timezone='UTC') if BackgroundScheduler else None
DB_INIT_ERROR = None

UPLOAD_DIR = os.path.join(STATIC_DIR, 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED_LOGO_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.webp', '.gif'}

OTP_EXPIRY = 300 
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_COOLDOWN = 60
PROTECTED_OTP_ROLES = {'admin', 'hod', 'principal', 'secretary'}
APPROVER_ROLES = {'hod', 'principal', 'secretary'}
SELF_SIGNUP_ROLES = {'student', 'staff', 'faculty'}
OTP_SESSION_CHALLENGE_KEY = 'pending_otp_challenge_id'
LOGIN_FAIL_THRESHOLD = 3
LOGIN_FAIL_WINDOW_SECONDS = 900
LOGIN_FAIL_NOTIFY_COOLDOWN_SECONDS = 900

_login_failures = {}


def utc_now_naive():
    """UTC now as naive datetime for DB DATETIME compatibility."""
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


def generate_otp():
    return str(secrets.randbelow(900000) + 100000)


def _build_in_clause(values):
    cleaned = [int(value) for value in (values or []) if value is not None]
    if not cleaned:
        return None, ()
    placeholders = ','.join(['%s'] * len(cleaned))
    return placeholders, tuple(cleaned)


def _get_request_meta():
    return {
        'ip': request.headers.get('X-Forwarded-For', request.remote_addr) or 'unknown',
        'user_agent': str(request.user_agent or ''),
        'path': request.path,
    }


def _log_security_event(category, severity, title, message, username=None, status_code=None):
    try:
        create_admin_alert(
            category=category,
            severity=severity,
            title=title,
            message=message,
            username=username or 'anonymous',
            endpoint=request.path,
            status_code=status_code,
        )
    except Exception:
        pass


def _get_admin_security_recipient():
    # Prefer explicit environment override, then stored app config, then SMTP settings.
    return (
        (os.environ.get('ADMIN_OTP_EMAIL') or '').strip()
        or (get_config('admin_otp_email') or '').strip()
        or (get_config('system_email') or '').strip()
        or (app.config.get('MAIL_DEFAULT_SENDER') or '').strip()
        or (app.config.get('MAIL_USERNAME') or '').strip()
    )


def _send_admin_security_email(subject, body):
    if not mail or not Message:
        return False
    recipient = _get_admin_security_recipient()
    if not recipient:
        return False

    message = Message(subject=subject, recipients=[recipient], sender=_resolve_email_sender())
    message.body = body
    send_email_in_thread(message)
    return True


def _record_login_failure(username):
    now = utc_now_naive()
    key = (username or 'unknown').lower()
    state = _login_failures.get(key)

    if not state:
        state = {'count': 0, 'first_at': now, 'last_notified': None}
    else:
        first_at = state.get('first_at')
        if not first_at or (now - first_at).total_seconds() > LOGIN_FAIL_WINDOW_SECONDS:
            state = {'count': 0, 'first_at': now, 'last_notified': None}

    state['count'] += 1
    _login_failures[key] = state
    return state


def _reset_login_failures(username):
    key = (username or 'unknown').lower()
    if key in _login_failures:
        _login_failures.pop(key, None)


def _handle_login_failure(username, reason, status_code=401):
    meta = _get_request_meta()
    state = _record_login_failure(username)
    message = (
        f"Login failed for '{username or 'unknown'}' ({reason}). "
        f"IP: {meta['ip']} | UA: {meta['user_agent']}"
    )
    _log_security_event(
        category='login-attempt',
        severity='medium',
        title='Login failed',
        message=message,
        username=username or 'unknown',
        status_code=status_code,
    )

    if state['count'] > LOGIN_FAIL_THRESHOLD:
        now = utc_now_naive()
        last_notified = state.get('last_notified')
        if not last_notified or (now - last_notified).total_seconds() > LOGIN_FAIL_NOTIFY_COOLDOWN_SECONDS:
            alert_message = (
                f"User '{username or 'unknown'}' has {state['count']} failed login attempts. "
                f"IP: {meta['ip']} | UA: {meta['user_agent']}"
            )
            _log_security_event(
                category='suspicious-action',
                severity='high',
                title='Repeated login failures',
                message=alert_message,
                username=username or 'unknown',
                status_code=status_code,
            )
            _send_admin_security_email(
                subject='Security alert: repeated login failures',
                body=alert_message,
            )
            state['last_notified'] = now
            _login_failures[(username or 'unknown').lower()] = state
     

def is_allowed_logo_file(filename):
    ext = os.path.splitext(filename or '')[1].lower()
    return ext in ALLOWED_LOGO_EXTENSIONS


def sync_smtp_runtime_config():
    """Keep runtime SMTP config in sync with admin-configured values."""
    email_value = (get_config('system_email') or '').strip()
    password_value = (get_config('smtp_password') or '').strip()

    if email_value:
        app.config['MAIL_USERNAME'] = email_value
        app.config['MAIL_DEFAULT_SENDER'] = email_value

    if password_value:
        app.config['MAIL_PASSWORD'] = password_value


def current_role():
    if session.get('is_admin'):
        return 'admin'
    return (session.get('login_type') or '').lower()


def role_requires_otp(role):
    r = (role or '').strip().lower()
    if r in PROTECTED_OTP_ROLES:
        return True
    from dataBase.db_init import get_approval_flow
    dynamic_approvers = {x.lower() for x in get_approval_flow()}
    return r in dynamic_approvers


def clear_pending_otp_session():
    session.pop(OTP_SESSION_CHALLENGE_KEY, None)
    session.pop('pending_otp_username', None)
    session.pop('pending_otp_role', None)


def clear_authenticated_session():
    session.pop('username', None)
    session.pop('is_admin', None)
    session.pop('login_type', None)


def redirect_for_role(role):
    role_key = (role or '').strip().lower()
    if role_key == 'admin':
        return redirect(url_for('admin_dashboard_page'))
    
    from dataBase.db_init import get_approval_flow
    dynamic_approvers = {x.lower() for x in get_approval_flow()}
    if role_key in dynamic_approvers or role_key in ('hod', 'principal', 'secretary'):
        return redirect(url_for('approver_dashboard_page'))
        
    if role_key in ('student', 'staff', 'faculty'):
        return redirect(url_for('requester_dashboard_page'))
        
    return redirect(url_for('home'))


def send_login_otp_email(recipient_email, username, role, otp):
    if not mail or not Message:
        return {'ok': False, 'message': 'Flask-Mail is not installed'}
    if not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
        return {'ok': False, 'message': 'Mail credentials are not configured'}

    sender = (
        (app.config.get('MAIL_DEFAULT_SENDER') or '').strip()
        or (app.config.get('MAIL_USERNAME') or '').strip()
        or (get_config('system_email') or '').strip()
    )
    if not sender:
        return {'ok': False, 'message': 'SMTP sender is not configured'}

    # Deduplicate: avoid sending the same OTP repeatedly within short window
    if _email_was_recently_sent(None, recipient_email, 'otp', window_seconds=60):
        return {'ok': False, 'message': 'OTP recently sent, suppressed'}

    message = Message(
        subject='Your Login OTP',
        recipients=[recipient_email],
        sender=sender,
    )
    message.body = (
        f"Hello {username},\n\n"
        f"Your OTP for Meeting Room Booking login is: {otp}\n"
        f"Role: {role}\n"
        f"This code will expire in {OTP_EXPIRY // 60} minutes.\n\n"
        "Do not share this code with anyone.\n"
        "If you did not try to log in, please contact the administrator."
    )
    send_email_in_thread(message)
    return {'ok': True}


def invalidate_existing_otp_challenges(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE login_otp_challenges
        SET consumed_at = UTC_TIMESTAMP()
        WHERE username = %s AND consumed_at IS NULL
        """,
        (username,),
    )
    conn.commit()
    conn.close()


def create_login_otp_challenge(username, role, email):
    otp = generate_otp()
    challenge_id = secrets.token_hex(16)
    otp_hash = generate_password_hash(otp)
    now_utc = utc_now_naive()
    expires_at = now_utc + datetime.timedelta(seconds=OTP_EXPIRY)
    resend_available_at = now_utc + datetime.timedelta(seconds=OTP_RESEND_COOLDOWN)

    invalidate_existing_otp_challenges(username)

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO login_otp_challenges (
            challenge_id,
            username,
            role,
            email,
            otp_hash,
            expires_at,
            failed_attempts,
            max_attempts,
            resend_available_at
        )
        VALUES (%s, %s, %s, %s, %s, %s, 0, %s, %s)
        """,
        (challenge_id, username, role, email, otp_hash, expires_at, OTP_MAX_ATTEMPTS, resend_available_at),
    )
    conn.commit()
    conn.close()

    mail_result = send_login_otp_email(email, username, role, otp)
    if not mail_result.get('ok'):
        consume_login_otp_challenge(challenge_id)
        return {'ok': False, 'message': mail_result.get('message') or 'Unable to send OTP'}

    return {'ok': True, 'challenge_id': challenge_id}


def get_login_otp_challenge(challenge_id):
    if not challenge_id:
        return None

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        """
        SELECT challenge_id, username, role, email, otp_hash, expires_at,
               failed_attempts, max_attempts, resend_available_at, consumed_at, created_at
        FROM login_otp_challenges
        WHERE challenge_id = %s
        """,
        (challenge_id,),
    )
    challenge = cursor.fetchone()
    conn.close()
    return challenge


def consume_login_otp_challenge(challenge_id):
    if not challenge_id:
        return

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE login_otp_challenges
        SET consumed_at = UTC_TIMESTAMP()
        WHERE challenge_id = %s AND consumed_at IS NULL
        """,
        (challenge_id,),
    )
    conn.commit()
    conn.close()


def increment_login_otp_attempt(challenge_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE login_otp_challenges
        SET failed_attempts = failed_attempts + 1
        WHERE challenge_id = %s AND consumed_at IS NULL
        """,
        (challenge_id,),
    )
    conn.commit()
    conn.close()


def get_pending_login_otp_challenge():
    challenge_id = session.get(OTP_SESSION_CHALLENGE_KEY)
    challenge = get_login_otp_challenge(challenge_id)
    if not challenge:
        clear_pending_otp_session()
        return None
    return challenge


def challenge_is_expired(challenge):
    expires_at = parse_datetime(challenge.get('expires_at')) if challenge else None
    return not expires_at or expires_at <= utc_now_naive()


def challenge_attempts_exhausted(challenge):
    if not challenge:
        return True
    return int(challenge.get('failed_attempts') or 0) >= int(challenge.get('max_attempts') or OTP_MAX_ATTEMPTS)


def seconds_until_resend_available(challenge):
    resend_at = parse_datetime(challenge.get('resend_available_at')) if challenge else None
    if not resend_at:
        return 0
    remaining = int((resend_at - utc_now_naive()).total_seconds())
    return max(0, remaining)


def ensure_user_exists_for_otp(username, role='admin', email=None):
    """Ensure a users-table row exists for OTP foreign-key compatibility."""
    username = (username or '').strip()
    if not username:
        return {'ok': False, 'message': 'username is required'}

    if len(username) > 20:
        return {'ok': False, 'message': 'Admin username is too long for users table (max 20 chars)'}

    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE username=%s", (username,))
        if cursor.fetchone():
            return {'ok': True}

        temp_password_hash = generate_password_hash(secrets.token_hex(16))
        cursor.execute(
            """
            INSERT INTO users (username, name, phone, email, role, department, hashed_password)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                username,
                'System Admin',
                '',
                (email or '').strip() or None,
                (role or 'admin').strip().lower(),
                'Administration',
                temp_password_hash,
            ),
        )
        conn.commit()
        return {'ok': True}
    except Exception as ex:
        return {'ok': False, 'message': str(ex)}
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def require_login(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('username'):
            return jsonify({'error': 'Unauthorized'}), 401
        return fn(*args, **kwargs)
    
    return wrapper


def require_roles(*allowed_roles):
    allowed = {role.lower() for role in allowed_roles}

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            role = current_role()
            
            if {'hod', 'principal', 'secretary'}.intersection(allowed):
                from dataBase.db_init import get_approval_flow
                dynamic_approvers = {r.lower() for r in get_approval_flow()}
                if role in dynamic_approvers:
                    return fn(*args, **kwargs)

            if 'student' in allowed or '__all__' in allowed:
                if role: return fn(*args, **kwargs)

            if role not in allowed:
                return jsonify({'error': 'Forbidden'}), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def notify_admin_new_signup(username, name, role):
    return create_signup_notification(username=username, name=name, role=role)


def get_system_health_snapshot():
    snapshot = {
        'database': {'ok': False, 'message': 'Unknown'},
        'email': {'ok': False, 'message': 'Unknown'},
        'api': {'ok': True, 'message': 'Running'},
        'system_load': {'ok': True, 'message': 'Normal'},
        'last_backup': {'ok': True, 'message': 'N/A'},
    }

    conn = None
    try:
        conn = get_connection()
        snapshot['database'] = {'ok': True, 'message': 'Connected'}
    except Exception as ex:
        snapshot['database'] = {'ok': False, 'message': str(ex)}
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

    mail_health = get_mail_health_status()
    snapshot['email'] = {
        'ok': bool(mail_health.get('ok')),
        'message': mail_health.get('message') or 'Unknown',
    }

    return snapshot


def report_failed_health_checks_to_admin(snapshot):
    for check_name, info in snapshot.items():
        if check_name == 'last_backup':
            continue
        if info.get('ok'):
            continue
        create_admin_alert(
            category='health-check',
            severity='high',
            title=f'{check_name.replace("_", " ").title()} check failed',
            message=info.get('message') or 'Unknown health check failure',
            username='admin',
            endpoint='/admin-dashboard.html',
            status_code=500,
        )

@app.before_request
def block_requests_when_startup_failed():
        # If DB bootstrap failed, route users to a readable diagnostics page.
        if DB_INIT_ERROR and request.endpoint not in {'startup_error_page', 'static'}:
                return redirect(url_for('startup_error_page'))


@app.after_request
def notify_admin_on_user_issues(response):
    """Create an admin alert when non-admin users hit server-side errors."""
    try:
        if response.status_code < 500:
            return response
        if (request.path or '').startswith('/api/admin'):
            return response

        username = session.get('username') or 'anonymous'
        if session.get('is_admin'):
            return response

        create_admin_alert(
            category='user-issue',
            severity='high',
            title='User encountered a server issue',
            message=f'Path: {request.path} returned {response.status_code}',
            username=username,
            endpoint=request.path,
            status_code=response.status_code,
        )
    except Exception:
        pass
    return response


@app.route('/startup-error')
def startup_error_page():
        if not DB_INIT_ERROR:
                return redirect(url_for('home'))

        db_host = os.environ.get('DB_HOST', 'localhost')
        db_user = os.environ.get('DB_USER', 'root')
        db_name = os.environ.get('DB_NAME', 'user_database')
        return (
                f"""
                <html>
                    <head>
                        <title>Startup Configuration Error</title>
                        <style>
                            body {{ font-family: Inter, Arial, sans-serif; background: #f3f4f6; padding: 30px; }}
                            .card {{ max-width: 820px; margin: 0 auto; background: #fff; border: 1px solid #d1d5db; border-radius: 12px; padding: 20px; }}
                            h1 {{ margin-top: 0; color: #991b1b; }}
                            code {{ background: #f9fafb; border: 1px solid #e5e7eb; padding: 2px 6px; border-radius: 6px; }}
                            pre {{ background: #111827; color: #f9fafb; padding: 12px; border-radius: 8px; overflow: auto; }}
                        </style>
                    </head>
                    <body>
                        <div class=\"card\">
                            <h1>App started, but database setup failed</h1>
                            <p>The server is running in safe mode. Please update your DB credentials and restart.</p>
                            <p><strong>Current target:</strong> host=<code>{db_host}</code>, user=<code>{db_user}</code>, database=<code>{db_name}</code></p>
                            <p><strong>Error:</strong></p>
                            <pre>{DB_INIT_ERROR}</pre>
                            <p>Set correct values in <code>.env</code>: <code>DB_HOST</code>, <code>DB_USER</code>, <code>DB_PASSWORD</code>, <code>DB_NAME</code>.</p>
                        </div>
                    </body>
                </html>
                """,
                503,
        )


def _fetch_request_context(request_id, role_name):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        """
        SELECT br.request_id, br.booking_id, br.room_no, br.purpose,
               br.requested_start, br.requested_end, br.user_comment,
               u.name AS requester_name, u.email AS requester_email,
               COALESCE(br.requester_department, u.department) AS requester_department,
               COALESCE(h.hall_name, CONCAT('Hall ', br.room_no)) AS hall_name,
               ra.action_token
        FROM booking_requests br
        JOIN request_approvals ra ON ra.request_id = br.request_id
        LEFT JOIN users u ON u.username = br.username
        LEFT JOIN halls h ON h.room_no = br.room_no
        WHERE br.request_id=%s AND ra.approver_role=%s
        LIMIT 1
        """,
        (request_id, role_name),
    )
    row = cursor.fetchone()
    conn.close()
    return row


def _fetch_approver_recipients(role_name, department=None):
    """Fetch approver recipients by role. For HOD, filters by department.
    Principal and Secretary receive requests from ALL departments."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    if role_name.upper() == 'HOD' and not (department and str(department).strip()):
        conn.close()
        return []

    if department and role_name.upper() == 'HOD':
                cursor.execute(
                        """
                        SELECT username, name, email
                        FROM users
                        WHERE LOWER(role)=LOWER(%s)
                            AND email IS NOT NULL
                            AND email <> ''
                            AND TRIM(LOWER(department)) = TRIM(LOWER(%s))
                        """,
                        (role_name, str(department).strip()),
                )
    else:
        cursor.execute(
            """
            SELECT username, name, email
            FROM users
            WHERE LOWER(role)=LOWER(%s)
              AND email IS NOT NULL
              AND email <> ''
            """,
            (role_name,),
        )
    rows = cursor.fetchall()
    conn.close()
    return rows


def _save_email_log(request_id, recipient_email, recipient_role, email_type, token):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO email_logs (request_id, recipient_email, recipient_role, email_type, token, status)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (request_id, recipient_email, recipient_role, email_type, token, 'sent'),
    )
    conn.commit()
    conn.close()


def _email_was_recently_sent(request_id, recipient_email, email_type, window_seconds=60):
    """Return True if a matching email log exists within the recent window.

    If `request_id` is None, the check ignores request_id and matches on recipient+type only.
    """
    if not recipient_email or not email_type:
        return False
    conn = get_connection()
    cursor = conn.cursor()
    if request_id is None:
        cursor.execute(
            """
            SELECT 1 FROM email_logs
            WHERE recipient_email=%s AND email_type=%s
              AND sent_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %s SECOND)
            LIMIT 1
            """,
            (recipient_email, email_type, window_seconds),
        )
    else:
        cursor.execute(
            """
            SELECT 1 FROM email_logs
            WHERE recipient_email=%s AND email_type=%s AND request_id=%s
              AND sent_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %s SECOND)
            LIMIT 1
            """,
            (recipient_email, email_type, request_id, window_seconds),
        )
    found = cursor.fetchone()
    conn.close()
    return bool(found)


def _build_approval_email_html(approver_name, role_name, context, approve_link, reject_link):
    """Build a professional HTML email for approvers with approve/reject buttons."""
    hall_display = context.get('hall_name') or f"Hall {context['room_no']}"
    requester_name = context.get('requester_name') or '-'
    requester_dept = context.get('requester_department') or '-'
    start_str = str(context.get('requested_start') or '-')
    end_str = str(context.get('requested_end') or '-')
    org_name = get_config('organization_name') or 'Meeting Hall System'
    user_comment = context.get('user_comment') or ''
    comment_html = f'''
                  <tr>
                    <td style="color:#64748b;font-size:13px;font-weight:600;">User Comment</td>
                    <td style="color:#1e293b;font-size:13px;">{user_comment}</td>
                  </tr>
    ''' if user_comment else ''

    return f"""
    <html>
    <body style="margin:0;padding:0;background:#f4f6f9;font-family:'Segoe UI',Arial,sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f9;padding:30px 0;">
    <tr><td align="center">
    <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,0.08);overflow:hidden;">

      <!-- Header -->
      <tr>
        <td style="background:linear-gradient(135deg,#1e3a5f,#2d5f8a);padding:28px 32px;text-align:center;">
          <h1 style="color:#ffffff;margin:0;font-size:22px;font-weight:600;">
            &#128197; Approval Required
          </h1>
          <p style="color:#a8c8e8;margin:6px 0 0;font-size:13px;">{org_name} &bull; Booking #{context['booking_id']}</p>
        </td>
      </tr>

      <!-- Body -->
      <tr>
        <td style="padding:28px 32px;">
          <p style="color:#333;font-size:15px;margin:0 0 18px;">Hello <strong>{approver_name}</strong>,</p>
          <p style="color:#555;font-size:14px;line-height:1.6;margin:0 0 20px;">
            A booking request requires your approval at the <strong>{role_name}</strong> stage.
          </p>

          <!-- Booking Details Card -->
          <table width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;margin-bottom:24px;">
            <tr>
              <td style="padding:18px 20px;">
                <table width="100%" cellpadding="4" cellspacing="0">
                  <tr>
                    <td style="color:#64748b;font-size:13px;font-weight:600;width:130px;">Booking ID</td>
                    <td style="color:#1e293b;font-size:13px;">#{context['booking_id']}</td>
                  </tr>
                  <tr>
                    <td style="color:#64748b;font-size:13px;font-weight:600;">Requester</td>
                    <td style="color:#1e293b;font-size:13px;">{requester_name}</td>
                  </tr>
                  <tr>
                    <td style="color:#64748b;font-size:13px;font-weight:600;">Department</td>
                    <td style="color:#1e293b;font-size:13px;">{requester_dept}</td>
                  </tr>
                  <tr>
                    <td style="color:#64748b;font-size:13px;font-weight:600;">Hall</td>
                    <td style="color:#1e293b;font-size:13px;">{hall_display}</td>
                  </tr>
                  <tr>
                    <td style="color:#64748b;font-size:13px;font-weight:600;">Purpose</td>
                    <td style="color:#1e293b;font-size:13px;">{context['purpose']}</td>
                  </tr>
                  <tr>
                    <td style="color:#64748b;font-size:13px;font-weight:600;">Start</td>
                    <td style="color:#1e293b;font-size:13px;">{start_str}</td>
                  </tr>
                  <tr>
                    <td style="color:#64748b;font-size:13px;font-weight:600;">End</td>
                    <td style="color:#1e293b;font-size:13px;">{end_str}</td>
                  </tr>
{comment_html}
                </table>
              </td>
            </tr>
          </table>

          <!-- Action Buttons -->
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td align="center" style="padding:8px 0;">
                <a href="{approve_link}"
                   style="display:inline-block;background:#16a34a;color:#ffffff;padding:12px 36px;
                          border-radius:8px;text-decoration:none;font-size:15px;font-weight:600;
                          margin-right:12px;box-shadow:0 2px 6px rgba(22,163,74,0.3);">
                  &#10004; Approve
                </a>
                <a href="{reject_link}"
                   style="display:inline-block;background:#dc2626;color:#ffffff;padding:12px 36px;
                          border-radius:8px;text-decoration:none;font-size:15px;font-weight:600;
                          box-shadow:0 2px 6px rgba(220,38,38,0.3);">
                  &#10006; Reject
                </a>
              </td>
            </tr>
          </table>

          <p style="color:#94a3b8;font-size:12px;margin:20px 0 0;text-align:center;">
            If the buttons don't work, copy and paste these links into your browser:<br>
            Approve: {approve_link}<br>
            Reject: {reject_link}
          </p>
        </td>
      </tr>

      <!-- Footer -->
      <tr>
        <td style="background:#f8fafc;border-top:1px solid #e2e8f0;padding:16px 32px;text-align:center;">
          <p style="color:#94a3b8;font-size:11px;margin:0;">
            This is an automated email from {org_name}. Please do not reply.
          </p>
        </td>
      </tr>

    </table>
    </td></tr>
    </table>
    </body>
    </html>
    """


def _build_status_email_html(user_name, booking_id, hall_display, purpose, start_str, end_str, new_status, approver_role, dashboard_url):
    """Build a professional HTML email notifying the requester of a status change."""
    org_name = get_config('organization_name') or 'Meeting Hall System'

    status_configs = {
        'Approved': {
            'badge_bg': '#16a34a', 'badge_text': '#ffffff',
            'icon': '&#127881;', 'title': 'Fully Approved!',
            'message': 'Your booking has been <strong>fully approved</strong> by all authorities. Your hall is confirmed!',
        },
        'Rejected': {
            'badge_bg': '#dc2626', 'badge_text': '#ffffff',
            'icon': '&#10060;', 'title': f'Rejected by {approver_role}',
            'message': f'Your booking has been <strong>rejected</strong> by <strong>{approver_role}</strong>.',
        },
    }

    if new_status.startswith('Pending_'):
        next_role = new_status[8:]
        cfg = {
            'badge_bg': '#f59e0b', 'badge_text': '#ffffff',
            'icon': '&#9989;', 'title': f'{approver_role} Approved',
            'message': f'Your booking has been <strong>approved by {approver_role}</strong> and is now pending <strong>{next_role}</strong> review.',
        }
    else:
        cfg = status_configs.get(new_status, {
            'badge_bg': '#6b7280', 'badge_text': '#ffffff',
            'icon': '&#128276;', 'title': 'Status Updated',
            'message': f'Your booking status has been updated to <strong>{new_status}</strong>.',
        })

    header_bg = '#16a34a' if new_status == 'Approved' else ('#dc2626' if new_status == 'Rejected' else '#1e3a5f')

    return f"""
    <html>
    <body style="margin:0;padding:0;background:#f4f6f9;font-family:'Segoe UI',Arial,sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f9;padding:30px 0;">
    <tr><td align="center">
    <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,0.08);overflow:hidden;">

      <!-- Header -->
      <tr>
        <td style="background:linear-gradient(135deg,{header_bg},{header_bg}cc);padding:28px 32px;text-align:center;">
          <h1 style="color:#ffffff;margin:0;font-size:22px;font-weight:600;">
            {cfg['icon']} {cfg['title']}
          </h1>
          <p style="color:rgba(255,255,255,0.75);margin:6px 0 0;font-size:13px;">{org_name} &bull; Booking #{booking_id}</p>
        </td>
      </tr>

      <!-- Body -->
      <tr>
        <td style="padding:28px 32px;">
          <p style="color:#333;font-size:15px;margin:0 0 18px;">Hello <strong>{user_name}</strong>,</p>

          <!-- Status Badge -->
          <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:20px;">
            <tr>
              <td align="center">
                <span style="display:inline-block;background:{cfg['badge_bg']};color:{cfg['badge_text']};
                             padding:8px 24px;border-radius:20px;font-size:14px;font-weight:600;">
                  {cfg['title']}
                </span>
              </td>
            </tr>
          </table>

          <p style="color:#555;font-size:14px;line-height:1.7;margin:0 0 20px;text-align:center;">
            {cfg['message']}
          </p>

          <!-- Booking Details Card -->
          <table width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;margin-bottom:24px;">
            <tr>
              <td style="padding:18px 20px;">
                <table width="100%" cellpadding="4" cellspacing="0">
                  <tr>
                    <td style="color:#64748b;font-size:13px;font-weight:600;width:120px;">Booking ID</td>
                    <td style="color:#1e293b;font-size:13px;">#{booking_id}</td>
                  </tr>
                  <tr>
                    <td style="color:#64748b;font-size:13px;font-weight:600;">Hall</td>
                    <td style="color:#1e293b;font-size:13px;">{hall_display}</td>
                  </tr>
                  <tr>
                    <td style="color:#64748b;font-size:13px;font-weight:600;">Purpose</td>
                    <td style="color:#1e293b;font-size:13px;">{purpose}</td>
                  </tr>
                  <tr>
                    <td style="color:#64748b;font-size:13px;font-weight:600;">Start</td>
                    <td style="color:#1e293b;font-size:13px;">{start_str}</td>
                  </tr>
                  <tr>
                    <td style="color:#64748b;font-size:13px;font-weight:600;">End</td>
                    <td style="color:#1e293b;font-size:13px;">{end_str}</td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>

          <!-- Dashboard Button -->
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td align="center" style="padding:8px 0;">
                <a href="{dashboard_url}"
                   style="display:inline-block;background:#1e3a5f;color:#ffffff;padding:12px 32px;
                          border-radius:8px;text-decoration:none;font-size:14px;font-weight:600;
                          box-shadow:0 2px 6px rgba(30,58,95,0.3);">
                  View Dashboard
                </a>
              </td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- Footer -->
      <tr>
        <td style="background:#f8fafc;border-top:1px solid #e2e8f0;padding:16px 32px;text-align:center;">
          <p style="color:#94a3b8;font-size:11px;margin:0;">
            This is an automated email from {org_name}. Please do not reply.
          </p>
        </td>
      </tr>

    </table>
    </td></tr>
    </table>
    </body>
    </html>
    """


def _resolve_email_sender():
    """Resolve the SMTP sender address from config."""
    return (
        (app.config.get('MAIL_DEFAULT_SENDER') or '').strip()
        or (app.config.get('MAIL_USERNAME') or '').strip()
        or (get_config('system_email') or '').strip()
    )


def get_base_url():
    """Dynamically get base URL for emails from request context or config."""
    try:
        from flask import request, has_request_context
        if has_request_context():
            return request.host_url.rstrip('/')
    except Exception:
        pass
    return app.config.get('APP_BASE_URL', 'http://localhost:5000').rstrip('/')


def send_approval_email_for_stage(request_id, role_name, department=None):
    """Send approval request email to the appropriate approver(s).
    For HOD: only the HOD of the requester's department receives the email.
    For Principal/Secretary: all users of that role receive the email."""
    if not mail or not Message:
        return {'ok': False, 'message': 'Flask-Mail is not installed'}
    if not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
        return {'ok': False, 'message': 'Mail credentials are not configured'}

    context = _fetch_request_context(request_id, role_name)
    if not context:
        return {'ok': False, 'message': 'Approval context not found'}

    # For HOD, use the department captured on the request itself when possible.
    effective_department = (department or context.get('requester_department') or '').strip() or None
    recipients = _fetch_approver_recipients(role_name, department=effective_department)
    if not recipients:
        return {'ok': False, 'message': f'No {role_name} recipients with email found'}

    base_url = get_base_url()
    approve_link = f"{base_url}/api/one-click/{context['action_token']}?decision=approve"
    reject_link = f"{base_url}/api/one-click/{context['action_token']}?decision=reject"

    sent = 0
    for approver in recipients:
        approver_name = approver.get('name') or approver.get('username')
        html_body = _build_approval_email_html(approver_name, role_name, context, approve_link, reject_link)

        message = Message(
            subject=f"Approval Needed: Booking #{context['booking_id']} ({role_name})",
            recipients=[approver['email']],
            sender=_resolve_email_sender(),
        )
        message.html = html_body
        message.body = (
            f"Hello {approver_name},\n\n"
            f"A booking request requires your action at {role_name} stage.\n"
            f"Booking ID: {context['booking_id']}\n"
            f"Requester: {context.get('requester_name') or '-'}\n"
            f"Department: {context.get('requester_department') or '-'}\n"
            f"Hall: {context.get('hall_name') or context['room_no']}\n"
            f"Purpose: {context['purpose']}\n"
            f"Start: {context['requested_start']}\n"
            f"End: {context['requested_end']}\n\n"
            f"Approve: {approve_link}\n"
            f"Reject: {reject_link}\n\n"
            "If link does not open, copy and paste it into your browser."
        )
        # Deduplicate per-approver: skip if an approval_request was recently sent
        if _email_was_recently_sent(context.get('request_id'), approver.get('email'), 'approval_request', window_seconds=60):
            # record suppressed log
            try:
                conn = get_connection()
                cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO email_logs (request_id, recipient_email, recipient_role, email_type, token, status)
                    VALUES (%s, %s, %s, %s, %s, 'suppressed')
                    """,
                    (context.get('request_id'), approver.get('email'), role_name, 'approval_request', context.get('action_token')),
                )
                conn.commit()
                conn.close()
            except Exception:
                pass
            continue

        send_email_in_thread(message)
        _save_email_log(context['request_id'], approver['email'], role_name, 'approval_request', context['action_token'])
        sent += 1

    return {'ok': True, 'sent': sent}


def send_requester_status_email(request_id, new_status, approver_role):
    """Send a status update email to the booking requester whenever the status changes."""
    if not mail or not Message:
        return {'ok': False, 'message': 'Flask-Mail is not installed'}
    if not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
        return {'ok': False, 'message': 'Mail credentials are not configured'}

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        """
        SELECT br.request_id, br.booking_id, br.room_no, br.purpose,
               br.requested_start, br.requested_end,
               u.name AS requester_name, u.email AS requester_email,
               COALESCE(h.hall_name, CONCAT('Hall ', br.room_no)) AS hall_name
        FROM booking_requests br
        LEFT JOIN users u ON u.username = br.username
        LEFT JOIN halls h ON h.room_no = br.room_no
        WHERE br.request_id=%s
        LIMIT 1
        """,
        (request_id,),
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return {'ok': False, 'message': 'Booking request not found'}

    recipient = (row.get('requester_email') or '').strip()
    if not recipient:
        return {'ok': False, 'message': 'Requester email is missing'}

    user_name = row.get('requester_name') or 'User'
    booking_id = row.get('booking_id') or str(request_id)
    hall_display = row.get('hall_name') or f"Hall {row['room_no']}"
    purpose = row.get('purpose') or '-'
    start_str = str(row.get('requested_start') or '-')
    end_str = str(row.get('requested_end') or '-')

    base_url = get_base_url()
    dashboard_url = f"{base_url}/requester-dashboard.html"

    # Determine email subject
    subject = f'Booking #{booking_id} — Status Update'
    plain_text_intro = f'Your booking status has been updated to {new_status}.'
    
    if new_status == 'Approved':
        subject = f'Booking #{booking_id} — Fully Approved! ✓'
        plain_text_intro = f'Congratulations! Your booking #{booking_id} has been fully approved!'
    elif new_status == 'Rejected':
        subject = f'Booking #{booking_id} — Rejected by {approver_role}'
        plain_text_intro = f'Your booking #{booking_id} has been rejected by {approver_role}.'
    elif new_status.startswith('Pending_'):
        next_role = new_status[8:]
        subject = f'Booking #{booking_id} — Approved by {approver_role}, Pending {next_role}'
        plain_text_intro = f'Your booking #{booking_id} has been approved by {approver_role} and is now pending {next_role} review.'

    html_body = _build_status_email_html(
        user_name, booking_id, hall_display, purpose, start_str, end_str,
        new_status, approver_role, dashboard_url
    )

    plain_text = (
        f"Hello {user_name},\n\n"
        f"{plain_text_intro}\n\n"
        f"Booking ID: #{booking_id}\n"
        f"Hall: {hall_display}\n"
        f"Purpose: {purpose}\n"
        f"Start: {start_str}\n"
        f"End: {end_str}\n\n"
        f"View your dashboard: {dashboard_url}\n"
    )

    # Deduplicate: skip if a similar status update was recently sent to the requester
    if _email_was_recently_sent(request_id, recipient, 'status_update', window_seconds=60):
        try:
            conn = get_connection()
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO email_logs (request_id, recipient_email, recipient_role, email_type, token, status)
                VALUES (%s, %s, %s, %s, %s, 'suppressed')
                """,
                (request_id, recipient, 'Requester', 'status_update', None),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass
        return {'ok': True, 'skipped': True, 'message': 'Status update recently sent, suppressed'}

    message = Message(subject=subject, recipients=[recipient], sender=_resolve_email_sender())
    message.html = html_body
    message.body = plain_text
    send_email_in_thread(message)
    _save_email_log(request_id, recipient, 'Requester', 'status_update', None)
    return {'ok': True}


def send_coordinator_email(request_id):
    if not mail or not Message:
        return
    
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT email, name FROM users WHERE role='coordinator'")
    coordinators = cursor.fetchall()
    
    if not coordinators:
        conn.close()
        return
        
    cursor.execute(
        """
        SELECT br.request_id, br.booking_id, br.room_no, br.purpose,
               br.requested_start, br.requested_end, br.equipment_needs,
               u.name AS requester_name, u.email AS requester_email, u.phone AS requester_phone,
               COALESCE(h.hall_name, CONCAT('Hall ', br.room_no)) AS hall_name
        FROM booking_requests br
        LEFT JOIN users u ON u.username = br.username
        LEFT JOIN halls h ON h.room_no = br.room_no
        WHERE br.request_id=%s
        LIMIT 1
        """,
        (request_id,)
    )
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return
        
    base_url = get_base_url()
    confirm_link = f"{base_url}/api/coordinator/confirm/{request_id}"
    
    for coord in coordinators:
        recipient = coord.get('email')
        if not recipient: continue
        
        if _email_was_recently_sent(request_id, recipient, 'coordinator_setup', window_seconds=60):
            continue
            
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <h2>Room Allocation Completed: Setup Required</h2>
            <p>Hello {coord.get('name') or 'Coordinator'},</p>
            <p>A booking has been fully approved and requires room setup.</p>
            <ul>
                <li><strong>Booking ID:</strong> {row.get('booking_id')}</li>
                <li><strong>Requester Name:</strong> {row.get('requester_name')}</li>
                <li><strong>Requester Phone:</strong> {row.get('requester_phone')}</li>
                <li><strong>Hall:</strong> {row.get('hall_name')}</li>
                <li><strong>Time:</strong> {row.get('requested_start')} to {row.get('requested_end')}</li>
                <li><strong>Equipment Needed:</strong> {row.get('equipment_needs') or 'None'}</li>
            </ul>
            <br>
            <a href="{confirm_link}" style="background-color: #2563eb; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Confirm Setup Complete</a>
        </body>
        </html>
        """
        
        message = Message(subject=f"Action Required: Setup for Booking #{row.get('booking_id')}",
                          recipients=[recipient],
                          sender=_resolve_email_sender())
        message.html = html_body
        send_email_in_thread(message)
        _save_email_log(request_id, recipient, 'coordinator', 'coordinator_setup', None)


def send_setup_complete_email(request_id):
    if not mail or not Message:
        return
        
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        """
        SELECT br.booking_id, br.room_no, COALESCE(h.hall_name, CONCAT('Hall ', br.room_no)) AS hall_name,
               u.email AS requester_email, u.name AS requester_name
        FROM booking_requests br
        LEFT JOIN users u ON u.username = br.username
        LEFT JOIN halls h ON h.room_no = br.room_no
        WHERE br.request_id=%s
        """, (request_id,)
    )
    row = cursor.fetchone()
    conn.close()
    
    if not row or not row.get('requester_email'):
        return
        
    recipient = row['requester_email']
    user_name = row['requester_name']
    booking_id = row['booking_id']
    hall_name = row['hall_name']
    
    if _email_was_recently_sent(request_id, recipient, 'setup_complete', window_seconds=60):
        return

    html_body = f"""
    <html>
    <body>
        <h2>Room Setup Complete</h2>
        <p>Hello {user_name},</p>
        <p>Your room setup for <strong>{hall_name}</strong> (Booking #{booking_id}) is now complete and ready for your use.</p>
    </body>
    </html>
    """
    
    message = Message(subject=f"Setup Complete: Booking #{booking_id}",
                      recipients=[recipient],
                      sender=_resolve_email_sender())
    message.html = html_body
    send_email_in_thread(message)
    _save_email_log(request_id, recipient, 'Requester', 'setup_complete', None)


def send_booking_submitted_email(request_id, username):
    """Send a confirmation email to the requester when a booking is submitted."""
    if not mail or not Message:
        return {'ok': False, 'message': 'Flask-Mail is not installed'}
    if not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
        return {'ok': False, 'message': 'Mail credentials are not configured'}

    user = get_user_details(username) or {}
    recipient = (user.get('email') or '').strip()
    if not recipient:
        return {'ok': False, 'message': 'User email is missing'}

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        """
        SELECT br.booking_id, br.room_no, br.purpose,
               br.requested_start, br.requested_end,
               COALESCE(h.hall_name, CONCAT('Hall ', br.room_no)) AS hall_name
        FROM booking_requests br
        LEFT JOIN halls h ON h.room_no = br.room_no
        WHERE br.request_id=%s
        LIMIT 1
        """,
        (request_id,),
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return {'ok': False, 'message': 'Booking not found'}

    user_name = user.get('name') or username
    booking_id = row.get('booking_id') or str(request_id)
    hall_display = row.get('hall_name') or f"Hall {row['room_no']}"
    org_name = get_config('organization_name') or 'Meeting Hall System'
    base_url = get_base_url()
    dashboard_url = f"{base_url}/requester-dashboard.html"

    html_body = f"""
    <html>
    <body style="margin:0;padding:0;background:#f4f6f9;font-family:'Segoe UI',Arial,sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f9;padding:30px 0;">
    <tr><td align="center">
    <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,0.08);overflow:hidden;">
      <tr>
        <td style="background:linear-gradient(135deg,#1e3a5f,#2d5f8a);padding:28px 32px;text-align:center;">
          <h1 style="color:#ffffff;margin:0;font-size:22px;font-weight:600;">&#128197; Booking Submitted</h1>
          <p style="color:#a8c8e8;margin:6px 0 0;font-size:13px;">{org_name} &bull; Booking #{booking_id}</p>
        </td>
      </tr>
      <tr>
        <td style="padding:28px 32px;">
          <p style="color:#333;font-size:15px;margin:0 0 18px;">Hello <strong>{user_name}</strong>,</p>
          <p style="color:#555;font-size:14px;line-height:1.7;margin:0 0 20px;text-align:center;">
            Your booking request has been <strong>submitted successfully</strong> and is now
            <strong>pending HOD approval</strong>.
          </p>
          <table width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;margin-bottom:24px;">
            <tr>
              <td style="padding:18px 20px;">
                <table width="100%" cellpadding="4" cellspacing="0">
                  <tr><td style="color:#64748b;font-size:13px;font-weight:600;width:120px;">Booking ID</td><td style="color:#1e293b;font-size:13px;">#{booking_id}</td></tr>
                  <tr><td style="color:#64748b;font-size:13px;font-weight:600;">Hall</td><td style="color:#1e293b;font-size:13px;">{hall_display}</td></tr>
                  <tr><td style="color:#64748b;font-size:13px;font-weight:600;">Purpose</td><td style="color:#1e293b;font-size:13px;">{row['purpose']}</td></tr>
                  <tr><td style="color:#64748b;font-size:13px;font-weight:600;">Start</td><td style="color:#1e293b;font-size:13px;">{row['requested_start']}</td></tr>
                  <tr><td style="color:#64748b;font-size:13px;font-weight:600;">End</td><td style="color:#1e293b;font-size:13px;">{row['requested_end']}</td></tr>
                </table>
              </td>
            </tr>
          </table>
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr><td align="center" style="padding:8px 0;"><a href="{dashboard_url}" style="display:inline-block;background:#1e3a5f;color:#ffffff;padding:12px 32px;border-radius:8px;text-decoration:none;font-size:14px;font-weight:600;">View Dashboard</a></td></tr>
          </table>
        </td>
      </tr>
      <tr>
        <td style="background:#f8fafc;border-top:1px solid #e2e8f0;padding:16px 32px;text-align:center;">
          <p style="color:#94a3b8;font-size:11px;margin:0;">This is an automated email from {org_name}. Please do not reply.</p>
        </td>
      </tr>
    </table>
    </td></tr>
    </table>
    </body>
    </html>
    """

    # Deduplicate booking-submitted confirmations
    if _email_was_recently_sent(request_id, recipient, 'booking_submitted', window_seconds=60):
        try:
            conn = get_connection()
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO email_logs (request_id, recipient_email, recipient_role, email_type, token, status)
                VALUES (%s, %s, %s, %s, %s, 'suppressed')
                """,
                (request_id, recipient, 'Requester', 'booking_submitted', None),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass
        return {'ok': True, 'skipped': True, 'message': 'Booking confirmation recently sent, suppressed'}

    message = Message(
        subject=f'Booking #{booking_id} Submitted — Pending HOD Approval',
        recipients=[recipient],
        sender=_resolve_email_sender(),
    )
    message.html = html_body
    message.body = (
        f"Hello {user_name},\n\n"
        f"Your booking request #{booking_id} has been submitted and is pending HOD approval.\n\n"
        f"Hall: {hall_display}\n"
        f"Purpose: {row['purpose']}\n"
        f"Start: {row['requested_start']}\n"
        f"End: {row['requested_end']}\n\n"
        f"Track your request: {dashboard_url}\n"
    )
    send_email_in_thread(message)
    _save_email_log(request_id, recipient, 'Requester', 'booking_submitted', None)
    return {'ok': True}


def send_alternative_slot_email(username, request_result):
    if not mail or not Message:
        return {'ok': False, 'message': 'Flask-Mail is not installed'}
    if not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
        return {'ok': False, 'message': 'Mail credentials are not configured'}

    user = get_user_details(username) or {}
    recipient = user.get('email')
    if not recipient:
        return {'ok': False, 'message': 'Requester email is missing'}

    req_id = request_result.get('request_id')
    suggestion_start = request_result.get('suggested_start')
    suggestion_end = request_result.get('suggested_end')
    if not req_id or not suggestion_start or not suggestion_end:
        return {'ok': False, 'message': 'No suggestion payload'}

    base_url = get_base_url()
    accept_url = f"{base_url}/requester-dashboard.html"
    # Deduplicate alternative-slot suggestions
    if _email_was_recently_sent(req_id, recipient, 'alternative_slot', window_seconds=60):
        try:
            conn = get_connection()
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO email_logs (request_id, recipient_email, recipient_role, email_type, token, status)
                VALUES (%s, %s, %s, %s, %s, 'suppressed')
                """,
                (req_id, recipient, user.get('role', 'Requester'), 'alternative_slot', None),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass
        return {'ok': True, 'skipped': True, 'message': 'Alternative suggestion recently sent, suppressed'}

    message = Message(
        subject=f"Alternative Slot Suggested for Booking #{request_result.get('booking_id')}",
        recipients=[recipient],
        sender=_resolve_email_sender(),
    )
    message.body = (
        f"Hello {user.get('name') or username},\n\n"
        "Your requested slot is currently full.\n"
        f"Suggested Start: {suggestion_start}\n"
        f"Suggested End: {suggestion_end}\n\n"
        f"Open dashboard and click Accept Suggestion: {accept_url}\n"
    )
    send_email_in_thread(message)
    _save_email_log(req_id, recipient, user.get('role', 'Requester'), 'alternative_slot', None)
    return {'ok': True}


def start_expiry_scheduler():
    if scheduler is None:
        return
    if scheduler.running:
        return
    scheduler.add_job(expire_stale_requests, trigger='interval', hours=1, id='expire_stale_requests', replace_existing=True)
    scheduler.start()


def get_mail_health_status():
    has_module = bool(mail and Message)
    config = {
        'mail_server': app.config.get('MAIL_SERVER'),
        'mail_port': app.config.get('MAIL_PORT'),
        'mail_use_tls': app.config.get('MAIL_USE_TLS'),
        'mail_use_ssl': app.config.get('MAIL_USE_SSL'),
        'has_username': bool(app.config.get('MAIL_USERNAME')),
        'has_password': bool(app.config.get('MAIL_PASSWORD')),
        'default_sender': app.config.get('MAIL_DEFAULT_SENDER'),
    }

    if not has_module:
        return {
            'ok': False,
            'module_ready': False,
            'config': config,
            'smtp_connection': False,
            'message': 'Flask-Mail package is unavailable',
        }

    if not config['has_username'] or not config['has_password']:
        return {
            'ok': False,
            'module_ready': True,
            'config': config,
            'smtp_connection': False,
            'message': 'MAIL_USERNAME or MAIL_PASSWORD is missing',
        }

    smtp_ok = False
    smtp_error = None
    server = None
    try:
        host = app.config.get('MAIL_SERVER')
        port = int(app.config.get('MAIL_PORT') or 0)
        use_ssl = bool(app.config.get('MAIL_USE_SSL'))
        use_tls = bool(app.config.get('MAIL_USE_TLS'))

        if use_ssl:
            server = smtplib.SMTP_SSL(host, port, timeout=12)
        else:
            server = smtplib.SMTP(host, port, timeout=12)
            server.ehlo()
            if use_tls:
                server.starttls()
                server.ehlo()

        server.login(app.config.get('MAIL_USERNAME'), app.config.get('MAIL_PASSWORD'))
        smtp_ok = True
    except Exception as ex:
        smtp_error = str(ex)
    finally:
        if server:
            try:
                server.quit()
            except Exception:
                pass

    return {
        'ok': smtp_ok,
        'module_ready': True,
        'config': config,
        'smtp_connection': smtp_ok,
        'message': 'SMTP connection successful' if smtp_ok else (smtp_error or 'SMTP connection failed'),
    }


def create_user_if_not_exists(username, name, phone, email, role, department, hashed_password):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT username FROM users WHERE username=%s", (username,))
    if cursor.fetchone():
        conn.close()
        return False

    cursor.execute(
        """
        INSERT INTO users (
            username,
            name,
            phone,
            email,
            role,
            department,
            hashed_password
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (username, name, phone, email, role, department, hashed_password)
    )
    conn.commit()
    conn.close()
    return True


def validate_user_credentials(username, password):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT hashed_password FROM users WHERE username=%s",
        (username,)
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return False

    return check_password_hash(row[0], password)


@app.route('/')
def home():
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard_page'))

    if session.get('username') :
        user = get_user_details(session.get('username'))
        # HOD
        if user and user.get('role', '').lower() == 'hod':
            return redirect(url_for('hod'))
        # PRINCIPAL
        elif user and user.get('role', '').lower() == 'principal':
            return redirect(url_for('principal'))
        
        # SECRETARY
        elif user and user.get('role', '').lower() == 'secretary':
            return redirect(url_for('secretary'))
        
        # STUDENT 
        elif user and user.get('role', '').lower() == 'student':
            return redirect(url_for('student'))

        # STAFF
        elif user and user.get('role', '').lower() == 'staff':
            return redirect(url_for('requester_dashboard_page'))
        
        # FACULTY
        elif user and user.get('role', '').lower() == 'faculty':
            return redirect(url_for('faculty'))

    return redirect(url_for('home_page'))

@app.route('/gallery.html')
def gallery():
    user = get_user_details(session.get('username')) if session.get('username') else None
    if session.get('username') and not user:
        user = {
            'username': session.get('username'),
            'name': session.get('username'),
            'role': current_role(),
        }
    config = get_all_config()
    return render_template('gallery.html', user=user, config=config)


@app.route('/login.html')
def login():
    if session.get('username'):
        return redirect(url_for('home'))
    config = get_all_config()
    error = (request.args.get('error') or '').strip()
    return render_template('login.html', config=config, error=error)

@app.route('/signup.html')
def signup():
    if session.get('username'):
        return redirect(url_for('home'))
    config = get_all_config()
    error = (request.args.get('error') or '').strip()
    return render_template('signup.html', config=config, error=error)

@app.route('/home.html')
def home_page():
    user = get_user_details(session.get('username')) if session.get('username') else None
    if session.get('username') and not user:
        user = {
            'username': session.get('username'),
            'name': session.get('username'),
            'role': current_role(),
        }
    config = get_all_config()
    return render_template('home.html', user=user, config=config)


@app.route('/home.css')
def home_css():
    return send_from_directory(TEMPLATE_DIR, 'home.css')


@app.route('/dashboard.css')
def dashboard_css():
    return send_from_directory(TEMPLATE_DIR, 'dashboard.css')


@app.route('/requester-dashboard.html')
@require_login
@require_roles('student', 'staff', 'faculty', 'hod', 'principal', 'secretary', 'admin')
def requester_dashboard_page():
    user = get_user_details(session.get('username')) if session.get('username') else None
    config = get_all_config()
    return render_template('requester_dashboard.html', user=user, config=config)


@app.route('/requester-booking.html')
@require_login
@require_roles('student', 'staff', 'faculty', 'hod', 'principal', 'secretary', 'admin')
def requester_booking_page():
    user = get_user_details(session.get('username')) if session.get('username') else None
    config = get_all_config()
    return render_template('requester_booking.html', user=user, config=config)


@app.route('/halls.html')
@require_login
@require_roles('student', 'staff', 'faculty', 'hod', 'principal', 'secretary', 'admin')
def halls_page():
    user = get_user_details(session.get('username')) if session.get('username') else None
    config = get_all_config()
    return render_template('halls.html', user=user, config=config)


@app.route('/settings.html')
@require_login
@require_roles('student', 'staff', 'faculty', 'hod', 'principal', 'secretary', 'admin')
def settings_page():
    user = get_user_details(session.get('username')) if session.get('username') else None
    config = get_all_config()
    return render_template('settings.html', user=user, role=current_role(), config=config)


@app.route('/api/user/profile', methods=['GET'])
@require_login
def api_user_profile():
    user = get_user_details(session.get('username'))
    if not user:
        return jsonify({'ok': False, 'message': 'User not found'}), 404
    return jsonify({'ok': True, **user}), 200


@app.route('/api/user/profile', methods=['PUT'])
@require_login
def api_update_user_profile():
    data = request.get_json(force=True, silent=True) or {}
    username = session.get('username')
    if not username:
        return jsonify({'ok': False, 'message': 'Not authenticated'}), 401

    # Email is NOT editable
    name = data.get('name', '').strip() or None
    phone = data.get('phone', '').strip() or None
    department = data.get('department', '').strip() or None

    try:
        updated = update_user_details(
            username=username,
            name=name,
            phone=phone,
            department=department,
        )
        if updated:
            return jsonify({'ok': True, 'message': 'Profile updated successfully'}), 200
        return jsonify({'ok': False, 'message': 'No changes made'}), 200
    except Exception as e:
        return jsonify({'ok': False, 'message': str(e)}), 500


@app.route('/api/user/change-password', methods=['POST'])
@require_login
def api_change_password():
    """Change password — requires old password. Approvers also need OTP."""
    data = request.get_json(force=True, silent=True) or {}
    username = session.get('username')
    if not username:
        return jsonify({'ok': False, 'message': 'Not authenticated'}), 401

    old_password = data.get('old_password', '').strip()
    new_password = data.get('new_password', '').strip()
    otp_code = data.get('otp', '').strip()

    if not old_password:
        return jsonify({'ok': False, 'message': 'Current password is required'}), 400
    if not new_password or len(new_password) < 6:
        return jsonify({'ok': False, 'message': 'New password must be at least 6 characters'}), 400

    # Verify old password
    if not validate_user_credentials(username, old_password):
        return jsonify({'ok': False, 'message': 'Current password is incorrect'}), 403

    # Approver roles require OTP verification
    role = current_role()
    if role in ('hod', 'principal', 'secretary'):
        if not otp_code:
            return jsonify({'ok': False, 'message': 'OTP is required for approver accounts', 'needs_otp': True}), 400

        # Verify OTP from the login_otp_challenges table
        challenge_id = session.get('settings_otp_challenge_id')
        if not challenge_id:
            return jsonify({'ok': False, 'message': 'Please request an OTP first', 'needs_otp': True}), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """SELECT otp_hash FROM login_otp_challenges
               WHERE id = %s AND username = %s AND consumed_at IS NULL
               AND expires_at > UTC_TIMESTAMP()""",
            (challenge_id, username),
        )
        challenge = cursor.fetchone()
        if not challenge:
            conn.close()
            session.pop('settings_otp_challenge_id', None)
            return jsonify({'ok': False, 'message': 'OTP expired or invalid. Request a new one.', 'needs_otp': True}), 400

        if not check_password_hash(challenge['otp_hash'], otp_code):
            conn.close()
            return jsonify({'ok': False, 'message': 'Incorrect OTP'}), 403

        # Consume the challenge
        cursor.execute(
            "UPDATE login_otp_challenges SET consumed_at = UTC_TIMESTAMP() WHERE id = %s",
            (challenge_id,),
        )
        conn.commit()
        conn.close()
        session.pop('settings_otp_challenge_id', None)

    try:
        updated = update_user_details(username=username, new_password=new_password)
        if updated:
            return jsonify({'ok': True, 'message': 'Password changed successfully'}), 200
        return jsonify({'ok': False, 'message': 'Password update failed'}), 500
    except Exception as e:
        return jsonify({'ok': False, 'message': str(e)}), 500


@app.route('/api/user/send-settings-otp', methods=['POST'])
@require_login
def api_send_settings_otp():
    """Send an OTP to the approver's email for password change verification."""
    username = session.get('username')
    role = current_role()
    if role not in ('hod', 'principal', 'secretary'):
        return jsonify({'ok': False, 'message': 'OTP not required for this role'}), 400

    user = get_user_details(username)
    if not user or not user.get('email'):
        return jsonify({'ok': False, 'message': 'No email address on file'}), 400

    import random
    otp = str(secrets.randbelow(100000, 999999))

    # Store OTP challenge
    conn = get_connection()
    cursor = conn.cursor()
    otp_hash = generate_password_hash(otp)
    invalidate_existing_otp_challenges(username)
    cursor.execute(
        """INSERT INTO login_otp_challenges (username, otp_hash, expires_at)
           VALUES (%s, %s, DATE_ADD(UTC_TIMESTAMP(), INTERVAL %s SECOND))""",
        (username, otp_hash, OTP_EXPIRY),
    )
    challenge_id = cursor.lastrowid
    conn.commit()
    conn.close()

    session['settings_otp_challenge_id'] = challenge_id

    result = send_login_otp_email(user['email'], username, role, otp)
    if result.get('ok'):
        return jsonify({'ok': True, 'message': f'OTP sent to {user["email"]}'}), 200
    return jsonify({'ok': False, 'message': result.get('message', 'Failed to send OTP')}), 500


@app.route('/api/user/delete-account', methods=['DELETE'])
@require_login
def api_delete_account():
    """Delete current user's account after password verification."""
    data = request.get_json(force=True, silent=True) or {}
    username = session.get('username').strip()
    if not username:
        return jsonify({'ok': False, 'message': 'Not authenticated'}), 401

    password = data.get('password', '').strip()
    if not password:
        return jsonify({'ok': False, 'message': 'Password is required to delete account'}), 400

    if not validate_user_credentials(username, password):
        return jsonify({'ok': False, 'message': 'Incorrect password'}), 403

    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username = %s", (username,))
        conn.commit()
        conn.close()
        clear_authenticated_session()
        return jsonify({'ok': True, 'message': 'Account deleted successfully'}), 200
    except Exception as e:
        return jsonify({'ok': False, 'message': str(e)}), 500


@app.route('/approver-dashboard.html')
@require_login
@require_roles('hod', 'principal', 'secretary')
def approver_dashboard_page():
    user = get_user_details(session.get('username')) if session.get('username') else None
    config = get_all_config()
    return render_template('approver_dashboard.html', user=user, role=current_role(), config=config)


@app.route('/approver-analytics.html')
@require_login
@require_roles('hod', 'principal', 'secretary')
def approver_analytics_page():
    user = get_user_details(session.get('username')) if session.get('username') else None
    config = get_all_config()
    return render_template('approver_analytics.html', user=user, role=current_role(), config=config)


@app.route('/api/approver/analytics', methods=['GET'])
@require_login
@require_roles('hod', 'principal', 'secretary')
def approver_analytics_api():
    try:
        role = current_role()
        user = get_user_details(session.get('username')) or {}
        department = (user.get('department') or '').strip()
        date_from = (request.args.get('date_from') or '').strip()
        date_to = (request.args.get('date_to') or '').strip()
        for label, value in (('date_from', date_from), ('date_to', date_to)):
            if value:
                try:
                    datetime.date.fromisoformat(value)
                except ValueError:
                    return jsonify({'ok': False, 'error': f'{label} must be YYYY-MM-DD'}), 400

        room_no = (request.args.get('room_no') or '').strip()
        if room_no:
            try:
                room_no = int(room_no)
            except ValueError:
                return jsonify({'ok': False, 'error': 'room_no must be a valid room number'}), 400

        filters = {
            'date_from': date_from,
            'date_to': date_to,
            'department': (request.args.get('department') or '').strip(),
            'room_no': room_no,
            'status': (request.args.get('status') or '').strip(),
        }
        data = get_approver_analytics(role, department, filters=filters)
        return jsonify({'ok': True, **data}), 200
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/admin-analytics.html')
@require_login
@require_roles('admin')
def admin_analytics_page():
    user = get_user_details(session.get('username')) if session.get('username') else None
    config = get_all_config()
    return render_template('admin_analytics.html', user=user, config=config)


@app.route('/admin-mail-health.html')
@require_login
@require_roles('admin')
def admin_mail_health_page():
    user = get_user_details(session.get('username')) if session.get('username') else None
    config = get_all_config()
    return render_template('admin_mail_health.html', user=user, config=config)

@app.route('/admin-config.html')
@require_login
@require_roles('admin')
def admin_config_page():
    user = get_user_details(session.get('username')) if session.get('username') else None
    config = get_all_config()
    return render_template('admin_config.html', user=user, config=config)

@app.route('/cart.html')
def cart():
    if session.get('username'):
        return redirect(url_for('requester_dashboard_page'))
    return redirect(url_for('home_page'))

@app.route('/signup', methods=['POST'])
def signup_post():
    try:
        name = (request.form.get('name') or '').strip()
        username = (request.form.get('username') or '').strip()
        phone = (request.form.get('phone') or '').strip()
        if not phone:
            return redirect(url_for('signup', error='Phone number is required'))
        email = (request.form.get('email') or '').strip()
        login_type = (request.form.get('login_type') or '').strip()
        department = (request.form.get('department') or '').strip()
        password = (request.form.get('password') or '').strip()
        hashed_password = generate_password_hash(password)
        if not username or not password:
            return "Username and password are required!", 400

        role = login_type.lower()
        if role not in SELF_SIGNUP_ROLES:
            return "This role cannot be self-registered. Please contact admin.", 403

        if len(username) > 20:
            return "Username is too long (max 20 characters).", 400

        if len(password) < 6:
            return "Password must be at least 6 characters.", 400

        created = create_user_if_not_exists(
            username=username,
            name=name,
            phone=phone,
            email=email,
            role=role,
            department=department,
            hashed_password=hashed_password,
        )

        if not created:
            return "Username already exists! Choose another one.", 409

        # Auto login after signup
        session['username'] = username
        session['login_type'] = role
        
        # Redirect based on user type
        if role in ['hod', 'principal', 'secretary', 'student', 'faculty']:
            # Notify admin about new registration
            notify_admin_new_signup(username, name, role)
            return redirect(url_for('home'))
        else:
            return redirect(url_for('home'))

    except Exception as e:
        return f"Signup error: {str(e)}", 500
    

@app.route('/login', methods=['POST'])
def login_post():
    try:
        username = (request.form.get('username') or '').strip()
        password = (request.form.get('password') or '').strip()

        if not username or not password:
            _handle_login_failure(username or 'unknown', 'missing credentials', status_code=400)
            return redirect(url_for('login', error='Username and password are required'))

        # Admin login from config
        admin_username = get_config('admin_username')
        admin_password = get_config('admin_password')
        
        if username == admin_username and password == admin_password:
            # If SMTP / Flask-Mail isn't configured, allow an explicit bypass
            # only when `ALLOW_ADMIN_NO_OTP` env var is truthy. This prevents
            # accidental admin access in environments without SMTP.
            mail_ready = bool(mail and Message and app.config.get('MAIL_USERNAME') and app.config.get('MAIL_PASSWORD'))
            allow_bypass = str(os.environ.get('ALLOW_ADMIN_NO_OTP', '')).strip().lower() in {'1', 'true', 'yes', 'on'}

            if not mail_ready:
                if allow_bypass:
                    meta = _get_request_meta()
                    _log_security_event(
                        category='login-attempt',
                        severity='low',
                        title='Admin login (no-OTP bypass enabled)',
                        message=f"Admin logged in without OTP because SMTP is not configured and ALLOW_ADMIN_NO_OTP is set. IP: {meta['ip']} | UA: {meta['user_agent']}",
                        username=admin_username,
                        status_code=200,
                    )
                    clear_authenticated_session()
                    session['username'] = admin_username
                    session['is_admin'] = True
                    session['login_type'] = 'admin'
                    return redirect_for_role('admin')
                # Inform the user what to do — require env var to enable bypass.
                return redirect(url_for('login', error='SMTP not configured. To allow local admin sign-in without OTP set ALLOW_ADMIN_NO_OTP=1'))

            admin_otp_email = (get_config('admin_otp_email') or 'slganeshkarthik@gmail.com').strip()
            if not admin_otp_email:
                return redirect(url_for('login', error='Admin OTP email is not configured'))

            ensure_admin_user = ensure_user_exists_for_otp(admin_username, role='admin', email=admin_otp_email)
            if not ensure_admin_user.get('ok'):
                return redirect(url_for('login', error=f"Admin OTP setup error: {ensure_admin_user.get('message') or 'Unable to prepare admin account'}"))

            challenge_result = create_login_otp_challenge(admin_username, 'admin', admin_otp_email)
            if not challenge_result.get('ok'):
                return redirect(url_for('login', error=challenge_result.get('message') or 'Unable to send OTP'))

            clear_authenticated_session()
            clear_pending_otp_session()
            session['is_admin'] = False
            session[OTP_SESSION_CHALLENGE_KEY] = challenge_result['challenge_id']
            session['pending_otp_username'] = admin_username
            session['pending_otp_role'] = 'admin'
            meta = _get_request_meta()
            _log_security_event(
                category='login-attempt',
                severity='low',
                title='Admin login OTP initiated',
                message=f"Admin OTP challenge created. IP: {meta['ip']} | UA: {meta['user_agent']}",
                username=admin_username,
                status_code=200,
            )
            return redirect(url_for('verify_otp_page'))

        if not validate_user_credentials(username, password):
            _handle_login_failure(username, 'invalid credentials', status_code=401)
            return redirect(url_for('login', error='Invalid username or password'))

        # Save login session
        user_details = get_user_details(username)
        user_type = (user_details or {}).get('role', '')
        user_email = ((user_details or {}).get('email') or '').strip()

        if not user_type:
            return redirect(url_for('login', error='User role not found'))

        if role_requires_otp(user_type):
            if not user_email:
                return redirect(url_for('login', error='Email is required for OTP verification'))

            challenge_result = create_login_otp_challenge(username, user_type, user_email)
            if not challenge_result.get('ok'):
                return redirect(url_for('login', error=challenge_result.get('message') or 'Unable to send OTP'))

            clear_authenticated_session()
            clear_pending_otp_session()
            session['is_admin'] = False
            session[OTP_SESSION_CHALLENGE_KEY] = challenge_result['challenge_id']
            session['pending_otp_username'] = username
            session['pending_otp_role'] = user_type
            return redirect(url_for('verify_otp_page'))

        session['username'] = username
        session['is_admin'] = False
        session['login_type'] = user_type

        _reset_login_failures(username)
        meta = _get_request_meta()
        _log_security_event(
            category='login-attempt',
            severity='low',
            title='Login succeeded',
            message=f"User '{username}' logged in. IP: {meta['ip']} | UA: {meta['user_agent']}",
            username=username,
            status_code=200,
        )
        
        # Check if user was trying to checkout
        if session.get('checkout_redirect'):
            session.pop('checkout_redirect')
            return redirect(url_for('checkout'))

        return redirect_for_role(user_type)

    except Exception as e:
        return redirect(url_for('login', error=f'Login error: {str(e)}'))


@app.route('/verify-otp', methods=['GET'])
def verify_otp_page():
    challenge = get_pending_login_otp_challenge()
    if not challenge:
        return redirect(url_for('login', error='OTP session expired. Please login again.'))

    if challenge.get('consumed_at') or challenge_is_expired(challenge) or challenge_attempts_exhausted(challenge):
        consume_login_otp_challenge(challenge.get('challenge_id'))
        clear_pending_otp_session()
        return redirect(url_for('login', error='OTP session expired. Please login again.'))

    return render_template(
        'verify_otp.html',
        username=challenge.get('username'),
        role=challenge.get('role'),
        email=challenge.get('email'),
        resend_seconds=seconds_until_resend_available(challenge),
        error=request.args.get('error'),
    )


@app.route('/verify-otp', methods=['POST'])
def verify_otp_post():
    challenge = get_pending_login_otp_challenge()
    if not challenge:
        return redirect(url_for('login', error='OTP session expired. Please login again.'))

    if challenge.get('consumed_at') or challenge_is_expired(challenge):
        consume_login_otp_challenge(challenge.get('challenge_id'))
        clear_pending_otp_session()
        return redirect(url_for('login', error='OTP expired. Please login again.'))

    if challenge_attempts_exhausted(challenge):
        consume_login_otp_challenge(challenge.get('challenge_id'))
        clear_pending_otp_session()
        return redirect(url_for('login', error='Maximum OTP attempts reached. Please login again.'))

    user_otp = (request.form.get('otp') or '').strip()
    if not user_otp:
        return redirect(url_for('verify_otp_page', error='OTP is required'))

    if not check_password_hash(challenge['otp_hash'], user_otp):
        increment_login_otp_attempt(challenge['challenge_id'])
        refreshed = get_login_otp_challenge(challenge['challenge_id'])
        meta = _get_request_meta()
        _log_security_event(
            category='otp-failure',
            severity='medium',
            title='OTP verification failed',
            message=(
                f"Invalid OTP for '{challenge.get('username')}'. "
                f"IP: {meta['ip']} | UA: {meta['user_agent']}"
            ),
            username=challenge.get('username'),
            status_code=401,
        )
        if challenge_attempts_exhausted(refreshed):
            consume_login_otp_challenge(challenge['challenge_id'])
            clear_pending_otp_session()
            _log_security_event(
                category='otp-failure',
                severity='high',
                title='OTP attempts exhausted',
                message=(
                    f"OTP locked out for '{challenge.get('username')}'. "
                    f"IP: {meta['ip']} | UA: {meta['user_agent']}"
                ),
                username=challenge.get('username'),
                status_code=401,
            )
            return redirect(url_for('login', error='Maximum OTP attempts reached. Please login again.'))
        return redirect(url_for('verify_otp_page', error='Invalid OTP'))

    consume_login_otp_challenge(challenge['challenge_id'])
    clear_pending_otp_session()
    role_key = (challenge.get('role') or '').strip().lower()
    is_admin_login = role_key == 'admin'
    session['username'] = challenge['username']
    session['is_admin'] = is_admin_login
    session['login_type'] = 'admin' if is_admin_login else challenge['role']

    _reset_login_failures(challenge['username'])
    meta = _get_request_meta()
    _log_security_event(
        category='login-attempt',
        severity='low',
        title='Login succeeded (OTP)',
        message=f"User '{challenge['username']}' logged in via OTP. IP: {meta['ip']} | UA: {meta['user_agent']}",
        username=challenge['username'],
        status_code=200,
    )

    if is_admin_login:
        health_snapshot = get_system_health_snapshot()
        session['admin_login_health_report'] = health_snapshot
        report_failed_health_checks_to_admin(health_snapshot)

    return redirect_for_role(challenge['role'])


@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    challenge = get_pending_login_otp_challenge()
    if not challenge:
        return redirect(url_for('login', error='OTP session expired. Please login again.'))

    if challenge.get('consumed_at') or challenge_is_expired(challenge) or challenge_attempts_exhausted(challenge):
        consume_login_otp_challenge(challenge.get('challenge_id'))
        clear_pending_otp_session()
        return redirect(url_for('login', error='OTP session expired. Please login again.'))

    resend_seconds = seconds_until_resend_available(challenge)
    if resend_seconds > 0:
        return redirect(url_for('verify_otp_page', error=f'Resend available in {resend_seconds} seconds'))

    new_challenge = create_login_otp_challenge(challenge['username'], challenge['role'], challenge['email'])
    if not new_challenge.get('ok'):
        return redirect(url_for('verify_otp_page', error=new_challenge.get('message') or 'Unable to resend OTP'))

    clear_pending_otp_session()
    session[OTP_SESSION_CHALLENGE_KEY] = new_challenge['challenge_id']
    session['pending_otp_username'] = challenge['username']
    session['pending_otp_role'] = challenge['role']
    return redirect(url_for('verify_otp_page'))


# ──────────────────────────────────────────────────────────────────────────────
# Forgot Password – OTP-based self-service reset (users & approvers, NOT admin)
# ──────────────────────────────────────────────────────────────────────────────

@app.route('/forgot-password.html')
def forgot_password_page():
    """Serve the multi-step forgot-password UI."""
    if session.get('username'):
        return redirect(url_for('home'))
    config = get_all_config()
    return render_template('forgot_password.html', config=config)


@app.route('/api/forgot-password/request-otp', methods=['POST'])
def api_forgot_password_request_otp():
    """Step 1 (and resend): generate & email a reset OTP.

    The request body is JSON:
      { "username": "...", "resend": false }
    On a resend, `resend: true` is passed and the username is read from the
    session key set in the first call.
    """
    data = request.get_json(force=True, silent=True) or {}
    is_resend = bool(data.get('resend'))

    if is_resend:
        username = session.get('forgot_pw_username')
        if not username:
            return jsonify({'ok': False, 'message': 'Session expired. Please start over.'}), 400
    else:
        username = (data.get('username') or '').strip()
        if not username:
            return jsonify({'ok': False, 'message': 'Username is required.'}), 400

    # Block admin from using this flow
    admin_username = (get_config('admin_username') or os.environ.get('ADMIN_USERNAME', 'admin')).strip()
    if username.lower() == admin_username.lower():
        return jsonify({'ok': False, 'message': 'Admin accounts cannot use self-service password reset.'}), 403

    user = get_user_details(username)
    if not user:
        # Return the same generic message to prevent username enumeration
        return jsonify({'ok': False, 'message': 'No account found with that username, or it has no registered email.'}), 404

    email = (user.get('email') or '').strip()
    if not email:
        return jsonify({'ok': False, 'message': 'No email address is registered for this account. Please contact an administrator.'}), 400

    role = (user.get('role') or 'user').strip().lower()

    # Invalidate any prior challenge for this user
    invalidate_existing_otp_challenges(username)

    otp = generate_otp()
    challenge_id = secrets.token_hex(16)
    otp_hash = generate_password_hash(otp)
    now_utc = utc_now_naive()
    expires_at = now_utc + datetime.timedelta(seconds=OTP_EXPIRY)
    resend_available_at = now_utc + datetime.timedelta(seconds=OTP_RESEND_COOLDOWN)

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO login_otp_challenges (
            challenge_id, username, role, email, otp_hash,
            expires_at, failed_attempts, max_attempts, resend_available_at
        )
        VALUES (%s, %s, %s, %s, %s, %s, 0, %s, %s)
        """,
        (challenge_id, username, role, email, otp_hash, expires_at, OTP_MAX_ATTEMPTS, resend_available_at),
    )
    conn.commit()
    conn.close()

    # Send OTP email
    if not mail or not Message:
        return jsonify({'ok': False, 'message': 'Email service is not available.'}), 503

    sender = _resolve_email_sender()
    if not sender:
        return jsonify({'ok': False, 'message': 'SMTP sender not configured.'}), 503

    org_name = get_config('organization_name') or 'Meeting Hall System'
    msg = Message(
        subject=f'[{org_name}] Password Reset Code',
        recipients=[email],
        sender=sender,
    )
    msg.html = f"""
    <html>
    <body style="margin:0;padding:0;background:#f4f6f9;font-family:'Segoe UI',Arial,sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f9;padding:30px 0;">
    <tr><td align="center">
    <table width="520" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);overflow:hidden;">
      <tr>
        <td style="background:linear-gradient(135deg,#0f2748,#17375f);padding:26px 32px;text-align:center;">
          <h1 style="color:#fff;margin:0;font-size:20px;font-weight:700;">🔑 Password Reset</h1>
          <p style="color:rgba(255,255,255,.7);margin:6px 0 0;font-size:13px;">{org_name}</p>
        </td>
      </tr>
      <tr>
        <td style="padding:28px 32px;">
          <p style="color:#333;font-size:15px;margin:0 0 16px;">Hello <strong>{user.get('name') or username}</strong>,</p>
          <p style="color:#555;font-size:14px;line-height:1.6;margin:0 0 20px;">
            We received a request to reset your password. Use the code below:
          </p>
          <div style="background:#f1f5ff;border:2px dashed #c7d8f8;border-radius:10px;padding:20px;text-align:center;margin-bottom:20px;">
            <span style="font-size:36px;font-weight:900;letter-spacing:10px;color:#0f2748;">{otp}</span>
          </div>
          <p style="color:#94a3b8;font-size:12px;text-align:center;margin:0;">
            This code expires in <strong>5 minutes</strong>. Do not share it with anyone.<br>
            If you did not request a password reset, you can safely ignore this email.
          </p>
        </td>
      </tr>
      <tr>
        <td style="background:#f8fafc;border-top:1px solid #e2e8f0;padding:14px 32px;text-align:center;">
          <p style="color:#94a3b8;font-size:11px;margin:0;">This is an automated email from {org_name}. Please do not reply.</p>
        </td>
      </tr>
    </table>
    </td></tr>
    </table>
    </body>
    </html>
    """
    msg.body = (
        f"Hello {user.get('name') or username},\n\n"
        f"Your password reset code is: {otp}\n"
        f"This code expires in 5 minutes.\n\n"
        "If you did not request a password reset, please ignore this email."
    )
    send_email_in_thread(msg)

    # Persist state in session (no sensitive data – just enough to proceed)
    session['forgot_pw_username'] = username
    session['forgot_pw_challenge_id'] = challenge_id
    session.pop('forgot_pw_verified', None)

    return jsonify({'ok': True, 'message': f'Reset code sent to your registered email.'})


@app.route('/api/forgot-password/verify-otp', methods=['POST'])
def api_forgot_password_verify_otp():
    """Step 2: Verify the reset OTP.

    Body: { "otp": "123456" }
    On success sets session['forgot_pw_verified'] = True so the reset step
    can proceed.
    """
    data = request.get_json(force=True, silent=True) or {}
    otp_code = (data.get('otp') or '').strip()

    username = session.get('forgot_pw_username')
    challenge_id = session.get('forgot_pw_challenge_id')

    if not username or not challenge_id:
        return jsonify({'ok': False, 'message': 'Session expired. Please request a new code.'}), 400

    if not otp_code:
        return jsonify({'ok': False, 'message': 'OTP code is required.'}), 400

    challenge = get_login_otp_challenge(challenge_id)
    if not challenge or challenge.get('consumed_at'):
        session.pop('forgot_pw_username', None)
        session.pop('forgot_pw_challenge_id', None)
        return jsonify({'ok': False, 'message': 'Reset code is invalid or has already been used.'}), 400

    if challenge_is_expired(challenge):
        consume_login_otp_challenge(challenge_id)
        session.pop('forgot_pw_username', None)
        session.pop('forgot_pw_challenge_id', None)
        return jsonify({'ok': False, 'message': 'Reset code has expired. Please request a new one.'}), 400

    if challenge_attempts_exhausted(challenge):
        consume_login_otp_challenge(challenge_id)
        session.pop('forgot_pw_username', None)
        session.pop('forgot_pw_challenge_id', None)
        return jsonify({'ok': False, 'message': 'Too many incorrect attempts. Please request a new code.'}), 400

    if not check_password_hash(challenge['otp_hash'], otp_code):
        increment_login_otp_attempt(challenge_id)
        refreshed = get_login_otp_challenge(challenge_id)
        remaining = int(challenge.get('max_attempts', OTP_MAX_ATTEMPTS)) - int((refreshed or {}).get('failed_attempts', 0))
        return jsonify({'ok': False, 'message': f'Incorrect code. {max(0, remaining)} attempt(s) remaining.'}), 400

    # OTP correct – mark as verified (consume challenge so it can't be reused)
    consume_login_otp_challenge(challenge_id)
    session['forgot_pw_verified'] = True
    return jsonify({'ok': True})


@app.route('/api/forgot-password/reset-password', methods=['POST'])
def api_forgot_password_reset_password():
    """Step 3: Set the new password.

    Body: { "new_password": "..." }
    Requires the session to have been through the verify-otp step.
    """
    data = request.get_json(force=True, silent=True) or {}
    new_password = (data.get('new_password') or '').strip()

    username = session.get('forgot_pw_username')
    verified = session.get('forgot_pw_verified')

    if not username or not verified:
        return jsonify({'ok': False, 'message': 'Session invalid or OTP not verified. Please start over.'}), 400

    if not new_password or len(new_password) < 6:
        return jsonify({'ok': False, 'message': 'Password must be at least 6 characters.'}), 400

    # Double-check user still exists and is not admin
    user = get_user_details(username)
    if not user:
        return jsonify({'ok': False, 'message': 'Account not found.'}), 404

    admin_username = (get_config('admin_username') or os.environ.get('ADMIN_USERNAME', 'admin')).strip()
    if username.lower() == admin_username.lower():
        return jsonify({'ok': False, 'message': 'Admin accounts cannot use self-service password reset.'}), 403

    try:
        new_hash = generate_password_hash(new_password)
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET hashed_password = %s WHERE username = %s",
            (new_hash, username),
        )
        conn.commit()
        conn.close()
    except Exception as ex:
        return jsonify({'ok': False, 'message': f'Password update failed: {ex}'}), 500

    # Clean up session
    session.pop('forgot_pw_username', None)
    session.pop('forgot_pw_challenge_id', None)
    session.pop('forgot_pw_verified', None)

    _log_security_event(
        category='password-reset',
        severity='low',
        title='Password reset via forgot-password flow',
        message=f"User '{username}' successfully reset their password via the forgot-password OTP flow.",
        username=username,
        status_code=200,
    )

    return jsonify({'ok': True, 'message': 'Password reset successfully.'})


@app.route('/bookings/create', methods=['POST'])
@require_login
@require_roles('student', 'staff', 'faculty', 'hod', 'principal', 'secretary', 'admin')
def create_booking():
    try:
        username = session.get('username')
        payload = request.get_json(silent=True) or request.form
        room_no = int(payload.get('room_no'))
        purpose = (payload.get('purpose') or '').strip()
        start_datetime = payload.get('start_datetime')
        end_datetime = payload.get('end_datetime')
        number_of_persons = int(payload.get('number_of_persons') or 0)
        required_equipment = payload.get('required_equipment') or payload.get('equipment_needs')
        buffer_minutes = resolve_buffer_minutes(payload.get('buffer_minutes'))
        duration_minutes = int(payload.get('duration_minutes') or 0)
        user_comment = (payload.get('user_comment') or '').strip() or None

        if not purpose or not start_datetime or not end_datetime:
            return jsonify({"error": "purpose, start_datetime and end_datetime are required"}), 400

        if duration_minutes <= 0:
            start_dt = start_datetime.replace('T', ' ')
            end_dt = end_datetime.replace('T', ' ')
            # Fallback duration when UI doesn't send one explicitly.
            from datetime import datetime

            sdt = datetime.fromisoformat(start_dt)
            edt = datetime.fromisoformat(end_dt)
            duration_minutes = int((edt - sdt).total_seconds() // 60)

        document_path = None
        if 'supporting_document' in request.files:
            file_obj = request.files['supporting_document']
            if file_obj and file_obj.filename:
                safe_name = secure_filename(file_obj.filename)
                saved_name = f"{username}_{safe_name}"
                save_path = os.path.join(UPLOAD_DIR, saved_name)
                file_obj.save(save_path)
                document_path = f"/static/uploads/{saved_name}"

        # Extract time_slots for multi-slot bookings
        import json as _json
        time_slots_raw = payload.get('time_slots')
        time_slots = None
        if time_slots_raw:
            if isinstance(time_slots_raw, str):
                try:
                    time_slots = _json.loads(time_slots_raw)
                except (ValueError, TypeError):
                    time_slots = None
            elif isinstance(time_slots_raw, list):
                time_slots = time_slots_raw

        result = create_booking_request(
            username=username,
            room_no=room_no,
            purpose=purpose,
            number_of_persons=number_of_persons,
            required_equipment=required_equipment,
            start_datetime=start_datetime,
            end_datetime=end_datetime,
            duration_minutes=duration_minutes,
            buffer_minutes=buffer_minutes,
            document_path=document_path,
            time_slots=time_slots,
            user_comment=user_comment,
        )

        request_status = result.get('request_status')
        if request_status and request_status.startswith('Pending_'):
            next_role = request_status.split('_')[1]
            try:
                send_approval_email_for_stage(result['request_id'], next_role)
            except Exception:
                pass
            # Notify the requester that their booking was submitted
            try:
                send_booking_submitted_email(result['request_id'], username)
            except Exception:
                pass
        elif request_status == 'Approved':
            # Notify the requester that their booking was submitted and auto-approved
            try:
                send_booking_submitted_email(result['request_id'], username)
            except Exception:
                pass
        elif request_status == 'Waitlisted' and result.get('suggested_start'):
            try:
                send_alternative_slot_email(username, result)
            except Exception:
                pass

        return jsonify({"message": "booking request submitted", **result}), 201
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/notifications/pending/<role>', methods=['GET'])
def list_pending_notifications(role):
    try:
        notifications = get_pending_notifications_for_role(role)
        return jsonify(notifications), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/notifications/<int:notification_id>/action', methods=['POST'])
def update_notification_action(notification_id):
    try:
        payload = request.get_json(silent=True) or request.form
        role = (payload.get('role') or '').strip().lower()
        decision = (payload.get('decision') or '').strip().lower()

        if not role or not decision:
            _log_security_event(
                category='suspicious-action',
                severity='medium',
                title='Approval action missing fields',
                message=f"Missing role/decision in notification action {notification_id}",
                username=session.get('username') or 'anonymous',
                status_code=400,
            )
            return jsonify({"error": "role and decision are required"}), 400

        result = update_notification_stage(notification_id, role, decision)
        if result.get('ok'):
            _log_security_event(
                category='approval',
                severity='low',
                title='Notification approval action',
                message=f"Notification {notification_id} updated by {role} ({decision})",
                username=session.get('username') or 'anonymous',
                status_code=200,
            )
        else:
            _log_security_event(
                category='approval',
                severity='medium',
                title='Notification approval failed',
                message=f"Notification {notification_id} update failed for {role} ({decision})",
                username=session.get('username') or 'anonymous',
                status_code=400,
            )
        status_code = 200 if result.get('ok') else 400
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/bookings/my', methods=['GET'])
@require_login
def my_booking_requests():
    try:
        username = session.get('username')
        return jsonify(get_requests_for_user(username)), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/slots/waiting-count', methods=['GET'])
@require_login
def slot_waiting_count():
    try:
        room_no = int(request.args.get('room_no'))
        start_dt = request.args.get('start_datetime')
        end_dt = request.args.get('end_datetime')
        if not start_dt or not end_dt:
            return jsonify({'error': 'start_datetime and end_datetime are required'}), 400

        count = get_waiting_count(room_no, start_dt, end_dt)
        return jsonify({'room_no': room_no, 'waiting_count': count}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/slots/suggest', methods=['GET'])
@require_login
def suggest_slot():
    try:
        room_no = int(request.args.get('room_no'))
        start_dt = request.args.get('start_datetime')
        duration = int(request.args.get('duration_minutes') or 60)
        buffer_minutes = resolve_buffer_minutes(request.args.get('buffer_minutes'))
        suggestion = suggest_alternative_slot(room_no, start_dt, duration, buffer_minutes)
        if not suggestion:
            return jsonify({'message': 'No alternative slot found in lookahead window'}), 404

        return jsonify(
            {
                'suggested_start': suggestion['start'].strftime('%Y-%m-%d %H:%M:%S'),
                'suggested_end': suggestion['end'].strftime('%Y-%m-%d %H:%M:%S'),
            }
        ), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/slots/overview', methods=['GET'])
@require_login
def slot_overview():
    try:
        room_no = int(request.args.get('room_no'))
        date_value = (request.args.get('date') or '').strip()
        session_name = (request.args.get('session') or 'morning').strip().lower()
        duration_minutes = int(request.args.get('duration_minutes') or 60)
        buffer_minutes = resolve_buffer_minutes(request.args.get('buffer_minutes'))

        if not date_value:
            return jsonify({'error': 'date is required'}), 400
        if session_name not in {'morning', 'evening'}:
            return jsonify({'error': 'session must be morning or evening'}), 400
        if duration_minutes < 30:
            return jsonify({'error': 'duration_minutes must be at least 30'}), 400
        if buffer_minutes < 0:
            return jsonify({'error': 'buffer_minutes must be 0 or more'}), 400

        try:
            selected_date = datetime.date.fromisoformat(date_value)
        except ValueError:
            return jsonify({'error': 'date must be YYYY-MM-DD'}), 400

        session_bounds = {
            'morning': (5, 12),
            'evening': (12, 22),
        }
        start_hour, end_hour = session_bounds[session_name]
        window_start = datetime.datetime.combine(selected_date, datetime.time(hour=start_hour))
        window_end = datetime.datetime.combine(selected_date, datetime.time(hour=end_hour))

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT request_status, requested_start, requested_end, buffer_minutes
            FROM booking_requests
            WHERE room_no = %s
              AND request_status IN ('Pending_HOD', 'Pending_Principal', 'Pending_Secretary', 'Approved', 'Waitlisted')
                            AND DATE_SUB(requested_start, INTERVAL COALESCE(buffer_minutes, 0) MINUTE) < %s
                            AND DATE_ADD(requested_end, INTERVAL COALESCE(buffer_minutes, 0) MINUTE) > %s
            ORDER BY requested_start ASC, request_id ASC
            """,
            (room_no, window_end, window_start),
        )
        bookings = cursor.fetchall()
        conn.close()

        slot_step_minutes = duration_minutes + buffer_minutes

        def format_time_label(start_dt, end_dt):
            start_label = start_dt.strftime('%I:%M %p').lstrip('0') if hasattr(start_dt, 'strftime') else str(start_dt)
            end_label = end_dt.strftime('%I:%M %p').lstrip('0') if hasattr(end_dt, 'strftime') else str(end_dt)
            return f'{start_label.lower()} - {end_label.lower()}'

        slots = []
        now_local = datetime.datetime.now()

        if selected_date < now_local.date():
            return jsonify(
                {
                    'room_no': room_no,
                    'date': date_value,
                    'session': session_name,
                    'duration_minutes': duration_minutes,
                    'buffer_minutes': buffer_minutes,
                    'slots': [],
                }
            ), 200

        cursor_start = window_start
        while cursor_start + datetime.timedelta(minutes=duration_minutes) <= window_end:
            cursor_end = cursor_start + datetime.timedelta(minutes=duration_minutes)

            if selected_date == now_local.date() and cursor_start <= now_local:
                cursor_start += datetime.timedelta(minutes=slot_step_minutes)
                continue

            blocked = False
            waiting_count = 0
            approval_breakdown = {
                'pending_hod': 0,
                'hod_approved': 0,
                'principal_approved': 0,
                'secretary_approved': 0,
            }

            for booking in bookings:
                booking_status = booking.get('request_status')
                requested_start = parse_datetime(booking.get('requested_start'))
                requested_end = parse_datetime(booking.get('requested_end'))
                existing_buffer = int(booking.get('buffer_minutes') or 0)
                buffered_start = requested_start - datetime.timedelta(minutes=existing_buffer) if requested_start else None
                buffered_end = requested_end + datetime.timedelta(minutes=existing_buffer) if requested_end else None

                overlaps_effective = bool(
                    buffered_start
                    and buffered_end
                    and buffered_start < cursor_end
                    and buffered_end > cursor_start
                )

                if not overlaps_effective:
                    continue

                if booking_status == 'Waitlisted':
                    waiting_count += 1
                elif booking_status == 'Pending_HOD':
                    approval_breakdown['pending_hod'] += 1
                    waiting_count += 1
                elif booking_status == 'Pending_Principal':
                    approval_breakdown['hod_approved'] += 1
                    waiting_count += 1
                elif booking_status == 'Pending_Secretary':
                    approval_breakdown['principal_approved'] += 1
                    waiting_count += 1
                elif booking_status == 'Approved':
                    approval_breakdown['secretary_approved'] += 1
                    waiting_count += 1
                    blocked = True

            # Determine slot color/status based on approval breakdown
            if blocked:
                slot_status = 'blocked'
                slot_color = 'red'
                status_label = 'Fully Booked'
            elif approval_breakdown['principal_approved'] > 0:
                slot_status = 'principal_approved'
                slot_color = 'orange'
                status_label = 'Principal Approved'
            elif approval_breakdown['hod_approved'] > 0:
                slot_status = 'hod_approved'
                slot_color = 'yellow'
                status_label = 'HOD Approved'
            elif approval_breakdown['pending_hod'] > 0:
                slot_status = 'pending'
                slot_color = 'green'
                status_label = 'Available'
            else:
                slot_status = 'open'
                slot_color = 'green'
                status_label = 'Available'

            slots.append(
                {
                    'start_datetime': cursor_start.strftime('%Y-%m-%d %H:%M:%S'),
                    'end_datetime': cursor_end.strftime('%Y-%m-%d %H:%M:%S'),
                    'start_minutes': cursor_start.hour * 60 + cursor_start.minute,
                    'end_minutes': cursor_end.hour * 60 + cursor_end.minute,
                    'time_label': format_time_label(cursor_start, cursor_end),
                    'waiting_count': waiting_count,
                    'approval_breakdown': approval_breakdown,
                    'status': slot_color,
                    'status_key': slot_status,
                    'status_label': status_label,
                    'blocked': blocked,
                }
            )

            cursor_start += datetime.timedelta(minutes=slot_step_minutes)

        return jsonify(
            {
                'room_no': room_no,
                'date': date_value,
                'session': session_name,
                'duration_minutes': duration_minutes,
                'buffer_minutes': buffer_minutes,
                'slots': slots,
            }
        ), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/halls', methods=['GET'])
@require_login
def halls_for_booking():
    try:
        halls = [h for h in list_halls() if h.get('is_active')]
        return jsonify(halls), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/bookings/<int:request_id>/accept-suggestion', methods=['POST'])
@require_login
def accept_slot_suggestion(request_id):
    try:
        result = accept_suggested_slot(request_id, session.get('username'))
        if result.get('ok'):
            try:
                send_approval_email_for_stage(request_id, 'HOD')
            except Exception:
                pass
        code = 200 if result.get('ok') else 400
        return jsonify(result), code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/approvals/pending', methods=['GET'])
@require_login
@require_roles('hod', 'principal', 'secretary')
def approvals_for_current_role():
    try:
        role = current_role()
        user = get_user_details(session.get('username')) or {}
        department = user.get('department')
        return jsonify(get_pending_notifications_for_role(role, department)), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/approvals/summary', methods=['GET'])
@require_login
@require_roles('hod', 'principal', 'secretary')
def approvals_summary_for_current_role():
    try:
        role = current_role()
        user = get_user_details(session.get('username')) or {}
        department = (user.get('department') or '').strip()
        if role == 'hod' and not department:
            return (
                jsonify(
                    {
                        'ok': True,
                        'role': role,
                        'display_role': 'HOD',
                        'counts': {
                            'pending_action': 0,
                            'confirmed_events': 0,
                            'schedule_conflicts': 0,
                        },
                        'hall_utilization': [],
                        'recent_actions': [],
                    }
                ),
                200,
            )

        hod_scope = role == 'hod' and bool(department)
        role_map = {
            'hod': 'HOD',
            'principal': 'Principal',
            'secretary': 'Secretary',
        }
        approver_role = role_map.get(role)
        if not approver_role:
            return jsonify({'ok': False, 'error': 'invalid role'}), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        if hod_scope:
            cursor.execute(
                """
                SELECT COUNT(*) AS pending_count
                FROM request_approvals ra
                JOIN booking_requests br ON br.request_id = ra.request_id
                LEFT JOIN users u ON u.username = br.username
                WHERE ra.approver_role=%s
                  AND ra.decision='Pending'
                  AND COALESCE(u.department, '')=%s
                """,
                (approver_role, department),
            )
        else:
            cursor.execute(
                """
                SELECT COUNT(*) AS pending_count
                FROM request_approvals
                WHERE approver_role=%s AND decision='Pending'
                """,
                (approver_role,),
            )
        pending_count = int((cursor.fetchone() or {}).get('pending_count') or 0)

        if hod_scope:
            cursor.execute(
                """
                SELECT COUNT(*) AS confirmed_count
                FROM booking_requests br
                LEFT JOIN users u ON u.username = br.username
                WHERE br.request_status='Approved'
                  AND br.finalized_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 7 DAY)
                  AND COALESCE(u.department, '')=%s
                """,
                (department,),
            )
        else:
            cursor.execute(
                """
                SELECT COUNT(*) AS confirmed_count
                FROM booking_requests
                WHERE request_status='Approved'
                  AND finalized_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 7 DAY)
                """
            )
        confirmed_count = int((cursor.fetchone() or {}).get('confirmed_count') or 0)

        # Count rejected events in the same 7 day window so approvers can monitor rejections
        if hod_scope:
            cursor.execute(
                """
                SELECT COUNT(*) AS rejected_count
                FROM booking_requests br
                LEFT JOIN users u ON u.username = br.username
                WHERE br.request_status='Rejected'
                  AND br.finalized_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 7 DAY)
                  AND COALESCE(u.department, '')=%s
                """,
                (department,),
            )
        else:
            cursor.execute(
                """
                SELECT COUNT(*) AS rejected_count
                FROM booking_requests
                WHERE request_status='Rejected'
                  AND finalized_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 7 DAY)
                """
            )
        rejected_count = int((cursor.fetchone() or {}).get('rejected_count') or 0)

        if hod_scope:
            cursor.execute(
                """
                SELECT COUNT(*) AS conflict_count
                FROM booking_requests br
                LEFT JOIN users u ON u.username = br.username
                WHERE (br.request_status='Waitlisted' OR br.queue_position > 1)
                  AND COALESCE(u.department, '')=%s
                """,
                (department,),
            )
        else:
            cursor.execute(
                """
                SELECT COUNT(*) AS conflict_count
                FROM booking_requests
                WHERE request_status='Waitlisted'
                   OR queue_position > 1
                """
            )
        conflict_count = int((cursor.fetchone() or {}).get('conflict_count') or 0)

        if hod_scope:
            cursor.execute(
                """
                SELECT h.room_no,
                       COALESCE(h.hall_name, CONCAT('Hall ', h.room_no)) AS hall_name,
                       COUNT(br.request_id) AS booking_count
                FROM halls h
                LEFT JOIN booking_requests br ON br.room_no = h.room_no
                     AND br.request_status='Approved'
                     AND br.requested_start >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 30 DAY)
                LEFT JOIN users u ON u.username = br.username
                     AND COALESCE(u.department, '')=%s
                WHERE h.is_active = TRUE
                GROUP BY h.room_no, h.hall_name
                ORDER BY booking_count DESC, h.room_no ASC
                LIMIT 10
                """,
                (department,),
            )
        else:
            cursor.execute(
                """
                SELECT h.room_no,
                       COALESCE(h.hall_name, CONCAT('Hall ', h.room_no)) AS hall_name,
                       COUNT(br.request_id) AS booking_count
                FROM halls h
                LEFT JOIN booking_requests br ON br.room_no = h.room_no
                     AND br.request_status='Approved'
                     AND br.requested_start >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 30 DAY)
                WHERE h.is_active = TRUE
                GROUP BY h.room_no, h.hall_name
                ORDER BY booking_count DESC, h.room_no ASC
                LIMIT 10
                """
            )
        hall_utilization = cursor.fetchall()

        if hod_scope:
            cursor.execute(
                """
                SELECT br.request_id, br.booking_id, br.room_no, br.purpose,
                      COALESCE(h.hall_name, CONCAT('Hall ', br.room_no)) AS room_name,
                       br.requested_start, br.requested_end, br.request_status,
                       br.submitted_at, br.user_comment, ra.decision, ra.comment, ra.acted_at,
                       u.name AS requester_name, u.department AS requester_department
                FROM request_approvals ra
                JOIN booking_requests br ON br.request_id = ra.request_id
                LEFT JOIN users u ON u.username = br.username
                  LEFT JOIN halls h ON h.room_no = br.room_no
                WHERE ra.approver_role=%s
                  AND ra.decision != 'Pending'
                  AND COALESCE(u.department, '')=%s
                ORDER BY COALESCE(ra.acted_at, br.updated_at, br.submitted_at) DESC
                LIMIT 5
                """,
                (approver_role, department),
            )
        else:
            cursor.execute(
                """
                SELECT br.request_id, br.booking_id, br.room_no, br.purpose,
                      COALESCE(h.hall_name, CONCAT('Hall ', br.room_no)) AS room_name,
                       br.requested_start, br.requested_end, br.request_status,
                       br.submitted_at, br.user_comment, ra.decision, ra.comment, ra.acted_at,
                       u.name AS requester_name, u.department AS requester_department
                FROM request_approvals ra
                JOIN booking_requests br ON br.request_id = ra.request_id
                LEFT JOIN users u ON u.username = br.username
                  LEFT JOIN halls h ON h.room_no = br.room_no
                WHERE ra.approver_role=%s AND ra.decision != 'Pending'
                ORDER BY COALESCE(ra.acted_at, br.updated_at, br.submitted_at) DESC
                LIMIT 5
                """,
                (approver_role,),
            )
        recent_actions = cursor.fetchall()

        conn.close()

        return (
            jsonify(
                {
                    'ok': True,
                    'role': role,
                    'display_role': approver_role,
                    'counts': {
                        'pending_action': pending_count,
                        'confirmed_events': confirmed_count,
                        'rejected_events': rejected_count,
                        'schedule_conflicts': conflict_count,
                    },
                    'hall_utilization': hall_utilization,
                    'recent_actions': recent_actions,
                }
            ),
            200,
        )
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/approvals/history', methods=['GET'])
@require_login
@require_roles('hod', 'principal', 'secretary')
def approvals_history_for_current_role():
    try:
        role = current_role()
        user = get_user_details(session.get('username')) or {}
        department = (user.get('department') or '').strip()
        if role == 'hod' and not department:
            return jsonify({'ok': True, 'history': []}), 200

        hod_scope = role == 'hod' and bool(department)
        role_map = {
            'hod': 'HOD',
            'principal': 'Principal',
            'secretary': 'Secretary',
        }
        approver_role = role_map.get(role)
        if not approver_role:
            return jsonify({'ok': False, 'error': 'invalid role'}), 400

        limit = int(request.args.get('limit', '20'))
        limit = max(1, min(limit, 100))

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        if hod_scope:
            cursor.execute(
                """
                SELECT br.request_id, br.booking_id, br.room_no, br.purpose,
                      COALESCE(h.hall_name, CONCAT('Hall ', br.room_no)) AS room_name,
                       br.requested_start, br.requested_end, br.request_status,
                       br.submitted_at, br.user_comment, ra.decision, ra.comment, ra.acted_at,
                       u.name AS requester_name, u.department AS requester_department
                FROM request_approvals ra
                JOIN booking_requests br ON br.request_id = ra.request_id
                LEFT JOIN users u ON u.username = br.username
                  LEFT JOIN halls h ON h.room_no = br.room_no
                WHERE ra.approver_role=%s
                  AND ra.decision != 'Pending'
                  AND COALESCE(u.department, '')=%s
                ORDER BY COALESCE(ra.acted_at, br.updated_at, br.submitted_at) DESC
                LIMIT %s
                """,
                (approver_role, department, limit),
            )
        else:
            cursor.execute(
                """
                SELECT br.request_id, br.booking_id, br.room_no, br.purpose,
                      COALESCE(h.hall_name, CONCAT('Hall ', br.room_no)) AS room_name,
                       br.requested_start, br.requested_end, br.request_status,
                       br.submitted_at, br.user_comment, ra.decision, ra.comment, ra.acted_at,
                       u.name AS requester_name, u.department AS requester_department
                FROM request_approvals ra
                JOIN booking_requests br ON br.request_id = ra.request_id
                LEFT JOIN users u ON u.username = br.username
                  LEFT JOIN halls h ON h.room_no = br.room_no
                WHERE ra.approver_role=%s AND ra.decision != 'Pending'
                ORDER BY COALESCE(ra.acted_at, br.updated_at, br.submitted_at) DESC
                LIMIT %s
                """,
                (approver_role, limit),
            )
        rows = cursor.fetchall()
        
        if rows:
            req_ids = [r['request_id'] for r in rows]
            placeholders = ','.join(['%s'] * len(req_ids))
            cursor.execute(
                f"SELECT request_id, approver_role, comment FROM request_approvals WHERE request_id IN ({placeholders}) AND comment IS NOT NULL AND comment != ''",
                req_ids
            )
            approvals = cursor.fetchall()
            for r in rows:
                r['all_comments'] = [{'role': a['approver_role'], 'comment': a['comment']} for a in approvals if a['request_id'] == r['request_id']]

        conn.close()
        return jsonify({'ok': True, 'history': rows}), 200
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/bookings/<int:request_id>/decision', methods=['POST'])
@require_login
@require_roles('hod', 'principal', 'secretary')
def booking_decision(request_id):
    try:
        payload = request.get_json(silent=True) or request.form
        decision = (payload.get('decision') or '').strip().lower()
        comment = payload.get('comment')
        user = get_user_details(session.get('username')) or {}
        department = user.get('department')
        result = take_approval_action(request_id, current_role(), decision, comment, department)

        new_status = result.get('new_status')
        role_map = {'hod': 'HOD', 'principal': 'Principal', 'secretary': 'Secretary'}
        approver_role = role_map.get(current_role(), current_role())

        next_role = None
        if new_status and new_status.startswith('Pending_'):
            next_role = new_status[8:]

        if result.get('ok'):
            _log_security_event(
                category='approval',
                severity='low',
                title='Approval action recorded',
                message=(
                    f"{approver_role} set request {request_id} to {new_status}. "
                    f"Decision={decision}"
                ),
                username=session.get('username'),
                status_code=200,
            )
            # Notify the next approver in the chain
            if next_role:
                try:
                    send_approval_email_for_stage(request_id, next_role)
                except Exception:
                    pass

            # Notify the requester of the status change
            try:
                send_requester_status_email(request_id, new_status, approver_role)
                if new_status == 'Approved':
                    send_coordinator_email(request_id)
            except Exception:
                pass

        if not result.get('ok'):
            _log_security_event(
                category='approval',
                severity='medium',
                title='Approval action failed',
                message=f"Approval update failed for request {request_id}. Decision={decision}",
                username=session.get('username'),
                status_code=400,
            )
        code = 200 if result.get('ok') else 400
        return jsonify(result), code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/one-click/<token>', methods=['GET'])
def one_click_approval(token):
    try:
        decision = (request.args.get('decision') or '').strip().lower()
        if decision in ('approve', 'approved'):
            decision = 'approved'
        elif decision in ('reject', 'rejected'):
            decision = 'rejected'
        result = process_one_click_approval(token, decision, comment='Processed via one-click email')

        new_status = result.get('new_status')
        next_role = None
        if new_status and new_status.startswith('Pending_'):
            next_role = new_status[8:]

        # Determine which approver role processed this
        approver_role = result.get('approver_role', 'Approver')

        if result.get('ok') and result.get('request_id'):
            _log_security_event(
                category='approval',
                severity='low',
                title='One-click approval processed',
                message=(
                    f"Token approval set request {result['request_id']} to {new_status}. "
                    f"Decision={decision}"
                ),
                username=result.get('username') or 'system',
                status_code=200,
            )
            # Notify the next approver in the chain
            if next_role:
                try:
                    send_approval_email_for_stage(result['request_id'], next_role)
                except Exception:
                    pass

            # Notify the requester of the status change
            try:
                send_requester_status_email(result['request_id'], new_status, approver_role)
                if new_status == 'Approved':
                    send_coordinator_email(result['request_id'])
            except Exception:
                pass

        if not result.get('ok'):
            _log_security_event(
                category='approval',
                severity='medium',
                title='One-click approval failed',
                message=f"Token approval failed. Decision={decision}",
                username='system',
                status_code=400,
            )
        code = 200 if result.get('ok') else 400
        return jsonify(result), code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/coordinator/confirm/<int:request_id>', methods=['GET'])
def confirm_setup_complete(request_id):
    send_setup_complete_email(request_id)
    return """
    <html>
    <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
        <h2 style="color: #16a34a;">Setup Confirmed!</h2>
        <p>The requester has been notified that the room setup is complete.</p>
    </body>
    </html>
    """


@app.route('/api/admin/halls', methods=['GET'])
@require_login
@require_roles('admin')
def admin_list_halls():
    try:
        return jsonify(list_halls()), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/halls', methods=['POST'])
@require_login
@require_roles('admin')
def admin_upsert_hall():
    try:
        payload = request.get_json(silent=True) or request.form
        room_no_raw = payload.get('room_no')
        capacity_raw = payload.get('capacity')
        min_capacity_raw = payload.get('min_capacity')

        if room_no_raw is None or capacity_raw is None or min_capacity_raw is None:
            return jsonify({'error': 'room_no, capacity, and min_capacity are required'}), 400

        room_no = int(room_no_raw)
        hall_name = (payload.get('hall_name') or f'Hall {room_no}').strip()
        capacity = int(capacity_raw)
        min_capacity = int(min_capacity_raw)
        is_active = str(payload.get('is_active', 'true')).strip().lower() in {'true', '1', 'yes', 'on'}

        if room_no <= 0:
            return jsonify({'error': 'room_no must be greater than 0'}), 400

        if capacity <= 0:
            return jsonify({'error': 'capacity must be greater than 0'}), 400

        if min_capacity < 0:
            return jsonify({'error': 'min_capacity cannot be negative'}), 400

        if min_capacity > capacity:
            return jsonify({'error': 'min_capacity cannot be greater than capacity'}), 400

        if not hall_name:
            return jsonify({'error': 'hall_name cannot be empty'}), 400

        image_path = None
        if 'hall_image' in request.files:
            file = request.files['hall_image']
            if file and file.filename:
                filename = secure_filename(file.filename)
                ext = os.path.splitext(filename)[1]
                unique_filename = f"room_{room_no}_{secrets.token_hex(4)}{ext}"
                upload_dir = os.path.join(STATIC_DIR, 'uploads')
                os.makedirs(upload_dir, exist_ok=True)
                file.save(os.path.join(upload_dir, unique_filename))
                image_path = f"/static/uploads/{unique_filename}"

        upsert_hall(room_no, hall_name, capacity, min_capacity, is_active, image_path)
        return jsonify({'ok': True, 'message': 'hall saved'}), 200
    except ValueError:
        return jsonify({'error': 'room_no, capacity, and min_capacity must be valid integers'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/halls', methods=['DELETE'])
@require_login
@require_roles('admin')
def admin_delete_hall():
    try:
        payload = request.get_json(silent=True) or request.form
        # accept JSON body or form data or query string
        room_no_raw = None
        if isinstance(payload, dict):
            room_no_raw = payload.get('room_no')
        if room_no_raw is None:
            room_no_raw = request.args.get('room_no')

        if room_no_raw is None:
            return jsonify({'error': 'room_no is required'}), 400

        try:
            room_no = int(room_no_raw)
        except ValueError:
            return jsonify({'error': 'room_no must be an integer'}), 400

        # Perform hard delete (remove row from DB) as requested
        ok = delete_hall(room_no, soft=False)
        if ok:
            return jsonify({'ok': True, 'message': 'room removed'}), 200
        else:
            return jsonify({'error': 'room not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/bookings', methods=['GET'])
@require_login
@require_roles('admin')
def admin_list_bookings():
    try:
        limit = int(request.args.get('limit', '100'))
        limit = max(1, min(limit, 300))

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT br.request_id, br.booking_id, br.username, br.room_no, br.purpose,
                   br.requested_start, br.requested_end, br.request_status,
                   br.submitted_at, br.updated_at,
                   u.name AS requester_name, u.department AS requester_department
            FROM booking_requests br
            LEFT JOIN users u ON u.username = br.username
            ORDER BY COALESCE(br.updated_at, br.submitted_at) DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        conn.close()
        return jsonify({'ok': True, 'bookings': rows}), 200
    except ValueError:
        return jsonify({'ok': False, 'error': 'limit must be a valid integer'}), 400
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/admin/bookings/<int:request_id>/override', methods=['POST'])
@app.route('/api/bookings/<int:request_id>/override', methods=['POST'])
@require_login
@require_roles('admin', 'hod', 'principal', 'secretary')
def booking_override(request_id):
    try:
        payload = request.get_json(silent=True) or request.form
        new_status = (payload.get('new_status') or '').strip()
        reason = (payload.get('reason') or '').strip()
        if not new_status:
            return jsonify({'error': 'new_status is required'}), 400

        role = current_role()
        if role == 'hod':
            user = get_user_details(session.get('username')) or {}
            hod_department = (user.get('department') or '').strip().lower()
            if not hod_department:
                return jsonify({'error': 'HOD department is required for override'}), 403

            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                """
                SELECT u.department AS requester_department
                FROM booking_requests br
                LEFT JOIN users u ON u.username = br.username
                WHERE br.request_id=%s
                """,
                (request_id,),
            )
            row = cursor.fetchone()
            conn.close()
            requester_department = ((row or {}).get('requester_department') or '').strip().lower()
            if requester_department != hod_department:
                return jsonify({'error': 'HOD can only override requests from own department'}), 403

        ok = override_booking_status(request_id, new_status, reason, role)
        if not ok:
            return jsonify({'error': 'request not found'}), 404
        return jsonify({'message': 'status overridden'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/dashboard-summary', methods=['GET'])
@require_login
@require_roles('admin')
def admin_dashboard_summary():
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT COUNT(*) AS total_bookings FROM booking_requests")
        total_bookings = int((cursor.fetchone() or {}).get('total_bookings') or 0)

        cursor.execute(
            """
            SELECT COUNT(*) AS pending_approvals
            FROM booking_requests
            WHERE request_status IN (%s, %s, %s)
            """,
            ('Pending_HOD', 'Pending_Principal', 'Pending_Secretary'),
        )
        pending_approvals = int((cursor.fetchone() or {}).get('pending_approvals') or 0)

        cursor.execute("SELECT COUNT(*) AS active_users FROM users")
        active_users = int((cursor.fetchone() or {}).get('active_users') or 0)

        cursor.execute("SELECT COUNT(*) AS total_rooms FROM halls WHERE is_active=TRUE")
        total_rooms = int((cursor.fetchone() or {}).get('total_rooms') or 0)

        conn.close()

        return jsonify(
            {
                'ok': True,
                'stats': {
                    'total_bookings': total_bookings,
                    'pending_approvals': pending_approvals,
                    'active_users': active_users,
                    'total_rooms': total_rooms,
                },
            }
        ), 200
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/admin/approvers', methods=['GET'])
@require_login
@require_roles('admin')
def admin_list_approvers():
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT username, name, phone, email, role, department, created_at
            FROM users
            WHERE role IN (%s, %s, %s)
            ORDER BY
                CASE
                    WHEN role = 'hod' THEN 1
                    WHEN role = 'principal' THEN 2
                    WHEN role = 'secretary' THEN 3
                    ELSE 4
                END,
                created_at DESC
            """,
            ('hod', 'principal', 'secretary'),
        )
        rows = cursor.fetchall()
        conn.close()
        return jsonify({'ok': True, 'approvers': rows}), 200
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/admin/approvers', methods=['POST'])
@require_login
@require_roles('admin')
def admin_create_approver():
    try:
        payload = request.get_json(silent=True) or request.form

        username = (payload.get('username') or '').strip()
        name = (payload.get('name') or '').strip()
        phone = (payload.get('phone') or '').strip()
        email = (payload.get('email') or '').strip()
        role = (payload.get('role') or '').strip().lower()
        department = (payload.get('department') or '').strip() or 'Administration'
        password = (payload.get('password') or '').strip()

        if role not in APPROVER_ROLES:
            return jsonify({'ok': False, 'error': 'role must be one of hod, principal, secretary'}), 400

        if not username or not name or not email or not password:
            return jsonify({'ok': False, 'error': 'username, name, email and password are required'}), 400

        if len(username) > 20:
            return jsonify({'ok': False, 'error': 'username is too long (max 20 characters)'}), 400

        if len(password) < 6:
            return jsonify({'ok': False, 'error': 'password must be at least 6 characters'}), 400

        if '@' not in email:
            return jsonify({'ok': False, 'error': 'valid email is required'}), 400

        created = create_user_if_not_exists(
            username=username,
            name=name,
            phone=phone,
            email=email,
            role=role,
            department=department,
            hashed_password=generate_password_hash(password),
        )

        if not created:
            return jsonify({'ok': False, 'error': 'username already exists'}), 409

        return jsonify({'ok': True, 'message': 'approver account created successfully'}), 201
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/admin/users', methods=['GET'])
@require_login
@require_roles('admin')
def admin_list_users():
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT username, name, phone, email, role, department, created_at
            FROM users
            ORDER BY
                CASE
                    WHEN role = 'admin' THEN 1
                    WHEN role = 'hod' THEN 2
                    WHEN role = 'principal' THEN 3
                    WHEN role = 'secretary' THEN 4
                    ELSE 5
                END,
                created_at DESC
            """
        )
        rows = cursor.fetchall()
        conn.close()
        return jsonify({'ok': True, 'users': rows}), 200
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/admin/users/<username>', methods=['DELETE'])
@require_login
@require_roles('admin')
def admin_delete_user(username):
    target_username = (username or '').strip()
    if not target_username:
        return jsonify({'ok': False, 'error': 'username is required'}), 400

    if target_username == (session.get('username') or '').strip():
        return jsonify({'ok': False, 'error': 'you cannot delete the currently logged-in admin account'}), 400

    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT username FROM users WHERE username=%s", (target_username,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'ok': False, 'error': 'user not found'}), 404

        cursor.execute("SELECT request_id FROM booking_requests WHERE username=%s", (target_username,))
        request_ids = [row[0] for row in cursor.fetchall()]

        placeholders, id_params = _build_in_clause(request_ids)
        if placeholders:
            cursor.execute(
                f"DELETE FROM request_approvals WHERE request_id IN ({placeholders})",
                id_params,
            )
            cursor.execute(
                f"DELETE FROM email_logs WHERE request_id IN ({placeholders})",
                id_params,
            )

        cursor.execute("DELETE FROM notifications WHERE username=%s", (target_username,))
        cursor.execute("DELETE FROM booking_details WHERE username=%s", (target_username,))
        cursor.execute("DELETE FROM login_otp_challenges WHERE username=%s", (target_username,))
        cursor.execute("DELETE FROM booking_requests WHERE username=%s", (target_username,))
        cursor.execute("DELETE FROM users WHERE username=%s", (target_username,))

        conn.commit()
        conn.close()
        return jsonify({'ok': True, 'message': f'user {target_username} deleted successfully'}), 200
    except Exception as e:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass
        return jsonify({'ok': False, 'error': str(e)}), 500
@app.route('/api/admin/users/<username>', methods=['PUT'])
@require_login
@require_roles('admin')
def admin_update_user(username):
    target_username = (username or '').strip()
    if not target_username:
        return jsonify({'ok': False, 'error': 'username is required'}), 400

    data = request.json or {}
    name = data.get('name')
    email = data.get('email')
    phone = data.get('phone')
    department = data.get('department')
    password = data.get('password')

    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT username FROM users WHERE username=%s", (target_username,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'ok': False, 'error': 'user not found'}), 404

        fields = []
        values = []
        if name is not None:
            fields.append("name = %s")
            values.append(name.strip())
        if email is not None:
            fields.append("email = %s")
            values.append(email.strip())
        if phone is not None:
            fields.append("phone = %s")
            values.append(phone.strip())
        if department is not None:
            fields.append("department = %s")
            values.append(department.strip())
        if password:
            fields.append("hashed_password = %s")
            values.append(generate_password_hash(password))

        if not fields:
            conn.close()
            return jsonify({'ok': False, 'error': 'no fields provided to update'}), 400

        values.append(target_username)
        sql = f"UPDATE users SET {', '.join(fields)} WHERE username = %s"
        cursor.execute(sql, tuple(values))
        conn.commit()
        return jsonify({'ok': True, 'message': 'user credentials updated successfully'})
    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({'ok': False, 'error': str(e)}), 500
    finally:
        if conn:
            conn.close()



@app.route('/api/bookings/<int:request_id>/update-document', methods=['POST'])
@require_login
def update_document(request_id):
    try:
        username = session.get('username')
        if 'supporting_document' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
        
        file_obj = request.files['supporting_document']
        if not file_obj or not file_obj.filename:
            return jsonify({"error": "Empty file"}), 400
            
        safe_name = secure_filename(file_obj.filename)
        saved_name = f"{username}_{safe_name}"
        save_path = os.path.join(UPLOAD_DIR, saved_name)
        file_obj.save(save_path)
        document_path = f"/static/uploads/{saved_name}"
        
        success = update_booking_document(request_id, username, document_path)
        if success:
            return jsonify({"ok": True, "message": "Document updated successfully", "document_path": document_path}), 200
        else:
            return jsonify({"error": "Could not update document or unauthorized"}), 403
    except Exception as e:
        print("Error updating document:", e)
        return jsonify({"error": "Internal server error"}), 500


@app.route('/api/admin/analytics', methods=['GET'])
@require_login
@require_roles('admin')
def admin_analytics():
    try:
        date_from = (request.args.get('date_from') or '').strip()
        date_to = (request.args.get('date_to') or '').strip()
        for label, value in (('date_from', date_from), ('date_to', date_to)):
            if value:
                try:
                    datetime.date.fromisoformat(value)
                except ValueError:
                    return jsonify({'ok': False, 'error': f'{label} must be YYYY-MM-DD'}), 400

        room_no = (request.args.get('room_no') or '').strip()
        if room_no:
            try:
                room_no = int(room_no)
            except ValueError:
                return jsonify({'ok': False, 'error': 'room_no must be a valid room number'}), 400

        time_slot = (request.args.get('time_slot') or '').strip()
        if time_slot:
            try:
                time_slot = int(time_slot)
            except ValueError:
                return jsonify({'ok': False, 'error': 'time_slot must be a valid hour'}), 400
            if time_slot < 0 or time_slot > 23:
                return jsonify({'ok': False, 'error': 'time_slot must be between 0 and 23'}), 400

        filters = {
            'date_from': date_from,
            'date_to': date_to,
            'department': (request.args.get('department') or '').strip(),
            'room_no': room_no,
            'status': (request.args.get('status') or '').strip(),
            'user_role': (request.args.get('user_role') or '').strip(),
            'time_slot': time_slot,
        }
        return jsonify({'ok': True, **get_admin_analytics(filters=filters)}), 200
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/admin/expire-stale', methods=['POST'])
@require_login
@require_roles('admin')
def run_stale_expiry():
    try:
        updated = expire_stale_requests()
        return jsonify({'expired_requests': updated}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/mail/health', methods=['GET'])
@require_login
@require_roles('admin')
def admin_mail_health():
    try:
        return jsonify(get_mail_health_status()), 200
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/admin/mail/test', methods=['POST'])
@require_login
@require_roles('admin')
def admin_mail_test():
    try:
        if not mail or not Message:
            return jsonify({'ok': False, 'error': 'Flask-Mail package is unavailable'}), 400

        payload = request.get_json(silent=True) or request.form
        recipient = (payload.get('recipient') or app.config.get('MAIL_USERNAME') or '').strip()
        if not recipient:
            return jsonify({'ok': False, 'error': 'recipient is required'}), 400

        subject = (payload.get('subject') or 'MeetingRoomBooking SMTP test email').strip()
        body = (payload.get('body') or 'SMTP configuration is working.').strip()

        sender = (
            (app.config.get('MAIL_DEFAULT_SENDER') or '').strip()
            or (app.config.get('MAIL_USERNAME') or '').strip()
            or (get_config('system_email') or '').strip()
        )
        if not sender:
            return jsonify({'ok': False, 'error': 'SMTP sender is not configured. Set System Email first.'}), 400

        message = Message(subject=subject, recipients=[recipient], sender=sender)
        message.body = body
        mail.send(message)
        return jsonify({'ok': True, 'message': f'test email sent to {recipient}'}), 200
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/hod')
def hod():
    return redirect(url_for('approver_dashboard_page'))


@app.route('/principal')
def principal():
    return redirect(url_for('approver_dashboard_page'))


@app.route('/secretary')
def secretary():
    return redirect(url_for('approver_dashboard_page'))


@app.route('/student')
def student():
    return redirect(url_for('requester_dashboard_page'))


@app.route('/faculty')
def faculty():
    return redirect(url_for('requester_dashboard_page'))


@app.route('/staff')
def staff():
    return redirect(url_for('requester_dashboard_page'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/admin-dashboard.html')
@require_login
@require_roles('admin')
def admin_dashboard_page():
    user = get_user_details(session.get('username')) if session.get('username') else None
    config = get_all_config()
    return render_template('admin_dashboard.html', user=user, config=config)


@app.route('/admin_panel')
def admin_panel():
    return redirect(url_for('admin_dashboard_page'))


@app.route('/load_products')
def load_products():
    return redirect(url_for('home'))


@app.route('/checkout')
def checkout():
    return "Checkout"


# ─── Admin Configuration Routes ───────────────────────────────

@app.route('/api/admin/config', methods=['GET'])
@require_login
@require_roles('admin')
def get_admin_config():
    """Get all configuration values."""
    try:
        config = get_all_config()
        return jsonify({'ok': True, 'config': config}), 200
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/admin/config/<config_key>', methods=['GET', 'POST', 'PUT'])
@require_login
@require_roles('admin')
def manage_admin_config(config_key):
    """Get or update a specific configuration value."""
    try:
        if request.method == 'GET':
            value = get_config(config_key)
            return jsonify({'ok': True, 'config_key': config_key, 'config_value': value}), 200
        
        # POST or PUT to update
        payload = request.get_json(silent=True) or request.form
        config_value = payload.get('config_value') or payload.get('value')
        description = payload.get('description')
        
        if config_value is None:
            return jsonify({'ok': False, 'error': 'config_value is required'}), 400
        
        set_config(config_key, config_value, description)

        # If SMTP-related config changes, apply immediately in runtime config.
        if (config_key or '').strip().lower() in {'system_email', 'smtp_password'}:
            sync_smtp_runtime_config()

        return jsonify({
            'ok': True, 
            'message': 'Configuration updated successfully',
            'config_key': config_key,
            'config_value': config_value
        }), 200
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/admin/config-list', methods=['GET'])
@require_login
@require_roles('admin')
def list_admin_configs():
    """List all configuration keys and values."""
    try:
        config = get_all_config()
        config_list = [{'key': k, 'value': v} for k, v in config.items()]
        return jsonify({'ok': True, 'configs': config_list}), 200
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/admin/system-health', methods=['GET'])
@require_login
@require_roles('admin')
def get_admin_system_health():
    try:
        consume = str(request.args.get('consume_login_report', '0')).lower() in {'1', 'true', 'yes'}
        login_report = session.get('admin_login_health_report')
        if consume:
            session.pop('admin_login_health_report', None)

        snapshot = get_system_health_snapshot()
        return jsonify({'ok': True, 'checks': snapshot, 'login_report': login_report}), 200
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/admin/alerts', methods=['GET'])
@require_login
@require_roles('admin')
def get_admin_alerts():
    try:
        limit = int(request.args.get('limit', '20'))
        unread_only = str(request.args.get('unread_only', '1')).lower() in {'1', 'true', 'yes'}
        alerts = get_recent_admin_alerts(limit=limit, unread_only=unread_only)
        mark_as_read = str(request.args.get('mark_as_read', '1')).lower() in {'1', 'true', 'yes'}
        if mark_as_read and alerts:
            mark_admin_alerts_as_read([row.get('alert_id') for row in alerts])
        return jsonify({'ok': True, 'alerts': alerts}), 200
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/admin/logo', methods=['POST'])
@require_login
@require_roles('admin')
def upload_admin_logo():
    """Upload and set a new application logo."""
    try:
        logo_file = request.files.get('logo')
        if not logo_file or not logo_file.filename:
            return jsonify({'ok': False, 'error': 'logo file is required'}), 400

        if not is_allowed_logo_file(logo_file.filename):
            return jsonify({'ok': False, 'error': 'unsupported logo format'}), 400

        ext = os.path.splitext(secure_filename(logo_file.filename))[1].lower()
        file_name = f"logo_{uuid.uuid4().hex}{ext}"
        save_path = os.path.join(UPLOAD_DIR, file_name)
        logo_file.save(save_path)

        logo_url = f"/static/uploads/{file_name}"
        set_config('app_logo_path', logo_url, 'Application logo URL')

        return jsonify({'ok': True, 'message': 'Logo updated successfully', 'logo_url': logo_url}), 200
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


try:
    init_db()
except Exception as ex:
    DB_INIT_ERROR = str(ex)
    print(f"[startup] Database initialization failed: {DB_INIT_ERROR}")
else:
    # Apply admin-configured SMTP settings after DB is ready.
    sync_smtp_runtime_config()
    if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        start_expiry_scheduler()
atexit.register(lambda: scheduler.shutdown(wait=False) if scheduler and scheduler.running else None)


if __name__ == '__main__':
    from waitress import serve
    threads = int(os.environ.get('WAITRESS_THREADS', '8'))
    port = int(os.environ.get('PORT', '5000'))
    print(f"[INFO] Server starting with Waitress on http://0.0.0.0:{port}")
    print("Press Ctrl+C to quit")
    serve(app, host="0.0.0.0", port=port, threads=threads)
