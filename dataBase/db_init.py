import datetime
import os
import random
import secrets
from datetime import timedelta, timezone

import mysql.connector
from mysql.connector import pooling


PENDING_STATUSES = ("Pending_HOD", "Pending_Principal", "Pending_Secretary")
ACTIVE_STATUSES = PENDING_STATUSES + ("Approved", "Waitlisted")
MIN_BOOKING_MINUTES = 30
DEFAULT_BUFFER_MINUTES = 15
DEFAULT_BUFFER_CONFIG_KEY = "default_buffer_minutes"

# ---------------------------------------------------------------------------
# Connection pool – reuses connections instead of opening a new TCP socket
# for every single query.  This is the single biggest performance win.
# ---------------------------------------------------------------------------
_connection_pool = None


def _get_pool():
    """Lazily initialize and return the global connection pool."""
    global _connection_pool
    if _connection_pool is None:
        settings = _db_settings()
        _connection_pool = pooling.MySQLConnectionPool(
            pool_name="meetbook_pool",
            pool_size=10,
            pool_reset_session=True,
            host=settings["host"],
            port=settings["port"],
            user=settings["user"],
            password=settings["password"],
            database=settings["database"],
        )
    return _connection_pool


def resolve_buffer_minutes(buffer_minutes=None):
    if buffer_minutes is not None and str(buffer_minutes).strip() != "":
        parsed = int(buffer_minutes)
        if parsed < 0:
            raise ValueError("buffer_minutes must be 0 or more")
        return parsed

    configured = get_config(DEFAULT_BUFFER_CONFIG_KEY)
    try:
        parsed = int(configured)
        return parsed if parsed >= 0 else DEFAULT_BUFFER_MINUTES
    except (TypeError, ValueError):
        return DEFAULT_BUFFER_MINUTES


def _db_settings():
    return {
        "host": os.environ.get("DB_HOST", "localhost"),
        "port": int(os.environ.get("DB_PORT", "3306")),
        "user": os.environ.get("DB_USER", "root"),
        "password": os.environ.get("DB_PASSWORD", ""),
        "database": os.environ.get("DB_NAME", "user_database"),
    }


def _ensure_database_exists():
    settings = _db_settings()
    database_name = settings["database"]
    # Connect without selecting a database so first-run setup can create it.
    conn = mysql.connector.connect(
        host=settings["host"],
        port=settings["port"],
        user=settings["user"],
        password=settings["password"],
    )
    cursor = conn.cursor()
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{database_name}`")
    conn.commit()
    conn.close()


def get_connection():
    """Return a connection from the pool (fast) with fallback to direct connect."""
    try:
        return _get_pool().get_connection()
    except Exception:
        # Fallback: pool not yet ready (e.g. during init_db first run)
        settings = _db_settings()
        return mysql.connector.connect(
            host=settings["host"],
            port=settings["port"],
            user=settings["user"],
            password=settings["password"],
            database=settings["database"],
        )


def get_current_time():
    utc_now = datetime.datetime.now(timezone.utc)
    ist = utc_now + timedelta(hours=5, minutes=30)
    return ist.strftime("%Y-%m-%d %H:%M:%S")


def parse_datetime(value):
    if isinstance(value, datetime.datetime):
        return value
    if value is None:
        return None
    value = str(value).strip()
    try:
        return datetime.datetime.fromisoformat(value)
    except ValueError:
        return datetime.datetime.strptime(value, "%Y-%m-%d %H:%M:%S")


def _build_in_clause(values):
    cleaned = [int(value) for value in (values or []) if value is not None]
    if not cleaned:
        return None, ()
    placeholders = ','.join(['%s'] * len(cleaned))
    return placeholders, tuple(cleaned)


def _add_missing_columns(cursor, table_name, columns_with_definitions):
    cursor.execute(f"SHOW COLUMNS FROM {table_name}")
    existing = {row[0] for row in cursor.fetchall()}
    for column_name, definition in columns_with_definitions.items():
        if column_name not in existing:
            cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {definition}")


def init_db():
    _ensure_database_exists()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username VARCHAR(20) PRIMARY KEY,
            name VARCHAR(100),
            phone VARCHAR(15),
            email VARCHAR(100),
            role VARCHAR(20),
            department VARCHAR(30),
            hashed_password TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS halls (
            hall_id INT AUTO_INCREMENT PRIMARY KEY,
            room_no INT UNIQUE NOT NULL,
            hall_name VARCHAR(100),
            capacity INT NOT NULL DEFAULT 50,
            min_capacity INT NOT NULL DEFAULT 1,
            is_active BOOLEAN DEFAULT TRUE,
            image_path VARCHAR(255) NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    _add_missing_columns(
        cursor,
        "halls",
        {
            "min_capacity": "min_capacity INT NOT NULL DEFAULT 1",
            "image_path": "image_path VARCHAR(255) NULL",
        },
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS booking_requests (
            request_id BIGINT AUTO_INCREMENT PRIMARY KEY,
            booking_id VARCHAR(12) UNIQUE,
            room_no INT NOT NULL,
            purpose VARCHAR(255) NOT NULL,
            number_of_persons INT,
            equipment_needs TEXT,
            document_path VARCHAR(255),
            requested_start DATETIME NOT NULL,
            requested_end DATETIME NOT NULL,
            duration_minutes INT NOT NULL,
            buffer_minutes INT NOT NULL DEFAULT 15,
            queue_position INT NOT NULL DEFAULT 1,
            request_status VARCHAR(30) NOT NULL DEFAULT 'Pending_HOD',
            suggested_start DATETIME NULL,
            suggested_end DATETIME NULL,
            submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            approval_due_at DATETIME,
            finalized_at DATETIME,
            username VARCHAR(20),
            requester_department VARCHAR(30) NULL,
            FOREIGN KEY (username) REFERENCES users(username)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS request_approvals (
            approval_id BIGINT AUTO_INCREMENT PRIMARY KEY,
            request_id BIGINT NOT NULL,
            approver_role VARCHAR(20) NOT NULL,
            decision VARCHAR(20) NOT NULL DEFAULT 'Pending',
            comment TEXT,
            acted_at DATETIME NULL,
            action_token VARCHAR(128) UNIQUE,
            token_expires_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_request_role (request_id, approver_role),
            FOREIGN KEY (request_id) REFERENCES booking_requests(request_id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS email_logs (
            email_log_id BIGINT AUTO_INCREMENT PRIMARY KEY,
            request_id BIGINT NULL,
            recipient_email VARCHAR(120),
            recipient_role VARCHAR(20),
            email_type VARCHAR(40),
            token VARCHAR(128),
            sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            clicked_at DATETIME NULL,
            status VARCHAR(20) DEFAULT 'sent',
            FOREIGN KEY (request_id) REFERENCES booking_requests(request_id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS login_otp_challenges (
            challenge_id CHAR(32) PRIMARY KEY,
            username VARCHAR(20) NOT NULL,
            role VARCHAR(20) NOT NULL,
            email VARCHAR(100) NOT NULL,
            otp_hash TEXT NOT NULL,
            expires_at DATETIME NOT NULL,
            failed_attempts INT NOT NULL DEFAULT 0,
            max_attempts INT NOT NULL DEFAULT 5,
            resend_available_at DATETIME NOT NULL,
            consumed_at DATETIME NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (username) REFERENCES users(username)
        )
        """
    )

    # Backward compatibility tables used by old routes.
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS booking_details (
            booking_id VARCHAR(6) PRIMARY KEY,
            room_no INT NOT NULL,
            purpose VARCHAR(255),
            number_of_persons INT,
            required_equipment TEXT,
            start_datetime DATETIME NOT NULL,
            end_datetime DATETIME NOT NULL,
            username VARCHAR(20),
            approval_status VARCHAR(20) DEFAULT 'pending',
            approved BOOLEAN DEFAULT FALSE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (username) REFERENCES users(username)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS notifications (
            notification_id INT AUTO_INCREMENT PRIMARY KEY,
            event_type VARCHAR(20) NOT NULL,
            booking_id VARCHAR(12) NULL,
            purpose VARCHAR(255),
            start_time DATETIME NULL,
            end_time DATETIME NULL,
            name VARCHAR(100),
            role VARCHAR(20),
            username VARCHAR(20),
            current_stage VARCHAR(20) DEFAULT 'HOD',
            HODstatus VARCHAR(20) DEFAULT 'pending',
            pstatus VARCHAR(20) DEFAULT 'pending',
            sstatus VARCHAR(20) DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (username) REFERENCES users(username)
        )
        """
    )

    _add_missing_columns(
        cursor,
        "booking_requests",
        {
            "equipment_needs": "equipment_needs TEXT",
            "requester_department": "requester_department VARCHAR(30) NULL",
            "duration_minutes": "duration_minutes INT NOT NULL DEFAULT 60",
            "buffer_minutes": "buffer_minutes INT NOT NULL DEFAULT 15",
            "queue_position": "queue_position INT NOT NULL DEFAULT 1",
            "request_status": "request_status VARCHAR(30) NOT NULL DEFAULT 'Pending_HOD'",
            "suggested_start": "suggested_start DATETIME NULL",
            "suggested_end": "suggested_end DATETIME NULL",
            "approval_due_at": "approval_due_at DATETIME NULL",
            "document_path": "document_path VARCHAR(255) NULL",
            "time_slots": "time_slots TEXT NULL",
            "user_comment": "user_comment TEXT NULL",
        },
    )

    _add_missing_columns(
        cursor,
        "login_otp_challenges",
        {
            "role": "role VARCHAR(20) NOT NULL",
            "email": "email VARCHAR(100) NOT NULL",
            "otp_hash": "otp_hash TEXT NOT NULL",
            "expires_at": "expires_at DATETIME NOT NULL",
            "failed_attempts": "failed_attempts INT NOT NULL DEFAULT 0",
            "max_attempts": "max_attempts INT NOT NULL DEFAULT 5",
            "resend_available_at": "resend_available_at DATETIME NOT NULL",
            "consumed_at": "consumed_at DATETIME NULL",
            "created_at": "created_at DATETIME DEFAULT CURRENT_TIMESTAMP",
        },
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS app_config (
            config_id INT AUTO_INCREMENT PRIMARY KEY,
            config_key VARCHAR(100) UNIQUE NOT NULL,
            config_value TEXT,
            description VARCHAR(255),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS admin_alerts (
            alert_id BIGINT AUTO_INCREMENT PRIMARY KEY,
            category VARCHAR(40) NOT NULL,
            severity VARCHAR(20) NOT NULL DEFAULT 'high',
            title VARCHAR(120) NOT NULL,
            message TEXT,
            username VARCHAR(20) NULL,
            endpoint VARCHAR(255) NULL,
            status_code INT NULL,
            is_read BOOLEAN NOT NULL DEFAULT FALSE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    conn.commit()
    conn.close()

    # Create performance indexes (idempotent – uses IF NOT EXISTS equivalent)
    _create_indexes()

    # Re-initialize the connection pool now that DB + tables exist
    global _connection_pool
    _connection_pool = None  # force pool recreation with the correct database
    _get_pool()

    # Initialize default config values
    _initialize_default_config()


def _create_indexes():
    """Create indexes on frequently queried columns for fast lookups.

    Uses CREATE INDEX IF NOT EXISTS pattern (try/except for MySQL < 8.0).
    These indexes dramatically speed up:
    - Overlap checks (room_no + request_status + requested_start/end)
    - User booking lookups (username)
    - Analytics aggregations (submitted_at, request_status)
    - Approval chain lookups (request_id + approver_role)
    - Email log dedup checks (recipient_email + email_type + sent_at)
    - OTP challenge lookups (username + consumed_at)
    - Admin alert reads (is_read + created_at)
    """
    indexes = [
        # users
        ("idx_username", "users", "(username)"),

        # booking_requests – most queried table
        ("idx_br_room_status", "booking_requests", "(room_no, request_status)"),
        ("idx_br_username", "booking_requests", "(username)"),
        ("idx_br_status", "booking_requests", "(request_status)"),
        ("idx_br_submitted", "booking_requests", "(submitted_at)"),
        ("idx_br_room_start_end", "booking_requests", "(room_no, requested_start, requested_end)"),
        ("idx_br_dept", "booking_requests", "(requester_department)"),

        # request_approvals
        ("idx_ra_request_role", "request_approvals", "(request_id, approver_role)"),
        ("idx_ra_token", "request_approvals", "(action_token)"),
        ("idx_ra_decision", "request_approvals", "(decision)"),

        # email_logs – dedup and analytics
        ("idx_el_request", "email_logs", "(request_id)"),
        ("idx_el_recipient_type", "email_logs", "(recipient_email, email_type, sent_at)"),

        # login_otp_challenges
        ("idx_otp_user", "login_otp_challenges", "(username, consumed_at)"),

        # admin_alerts
        ("idx_alerts_read_created", "admin_alerts", "(is_read, created_at)"),

        # notifications (legacy)
        ("idx_notif_username", "notifications", "(username)"),

        # halls
        ("idx_halls_active", "halls", "(is_active, room_no)"),
    ]

    conn = get_connection()
    cursor = conn.cursor()
    for idx_name, table, columns in indexes:
        try:
            cursor.execute(f"CREATE INDEX {idx_name} ON {table} {columns}")
        except Exception:
            # Index already exists or table doesn't exist – safe to ignore
            pass
    conn.commit()
    conn.close()


def get_user_details(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT username, name, phone, email, role, department
        FROM users
        WHERE username = %s
        """,
        (username,),
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "username": row[0],
        "name": row[1],
        "phone": row[2],
        "email": row[3],
        "role": row[4],
        "department": row[5],
    }


def update_user_details(username, name=None, phone=None, email=None, department=None, new_password=None):
    """Update editable user fields.  Username and role cannot be changed."""
    conn = get_connection()
    cursor = conn.cursor()

    fields = []
    values = []
    if name is not None:
        fields.append("name = %s")
        values.append(name)
    if phone is not None:
        fields.append("phone = %s")
        values.append(phone)
    if email is not None:
        fields.append("email = %s")
        values.append(email)
    if department is not None:
        fields.append("department = %s")
        values.append(department)
    if new_password is not None:
        import bcrypt
        hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        fields.append("hashed_password = %s")
        values.append(hashed)

    if not fields:
        conn.close()
        return False

    values.append(username)
    sql = f"UPDATE users SET {', '.join(fields)} WHERE username = %s"
    cursor.execute(sql, tuple(values))
    conn.commit()
    updated = cursor.rowcount > 0
    conn.close()
    return updated


def get_hall_by_room(room_no):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM halls WHERE room_no=%s AND is_active=TRUE", (room_no,))
    hall = cursor.fetchone()
    conn.close()
    return hall


def upsert_hall(room_no, hall_name, capacity, min_capacity=1, is_active=True, image_path=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO halls (room_no, hall_name, capacity, min_capacity, is_active, image_path)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            hall_name=VALUES(hall_name),
            capacity=VALUES(capacity),
            min_capacity=VALUES(min_capacity),
            is_active=VALUES(is_active),
            image_path=COALESCE(VALUES(image_path), halls.image_path)
        """,
        (room_no, hall_name, capacity, min_capacity, is_active, image_path),
    )
    conn.commit()
    conn.close()


def list_halls():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM halls ORDER BY room_no")
    rows = cursor.fetchall()
    conn.close()
    return rows


def delete_hall(room_no, soft=True):
    """Soft-delete (mark inactive) or hard-delete a hall by room_no.

    Returns True if a row was affected.
    """
    conn = get_connection()
    cursor = conn.cursor()
    if soft:
        cursor.execute("UPDATE halls SET is_active=FALSE WHERE room_no=%s", (room_no,))
    else:
        cursor.execute("DELETE FROM halls WHERE room_no=%s", (room_no,))
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    return affected > 0


def get_approval_flow():
    flow_str = get_config("approval_flow")
    if flow_str:
        return [r.strip() for r in flow_str.split(",") if r.strip()]
    return ["HOD", "Principal", "Secretary"]

def _overlap_count(cursor, room_no, start_dt, end_dt):
    cursor.execute(
        """
                SELECT COUNT(*) AS overlap_count
        FROM booking_requests
        WHERE room_no = %s
          AND request_status != 'Rejected'
          AND request_status != 'Cancelled'
          AND %s < DATE_ADD(requested_end, INTERVAL COALESCE(buffer_minutes, 0) MINUTE)
          AND %s > DATE_SUB(requested_start, INTERVAL COALESCE(buffer_minutes, 0) MINUTE)
        """,
        (
            room_no,
            start_dt,
            end_dt,
        ),
    )
    row = cursor.fetchone()
    if isinstance(row, dict):
        return int(row.get("overlap_count", 0))
    return int(row[0] if row else 0)


def get_waiting_count(room_no, start_dt, end_dt):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM booking_requests
        WHERE room_no = %s
          AND request_status = 'Waitlisted'
                    AND %s < DATE_ADD(requested_end, INTERVAL COALESCE(buffer_minutes, 0) MINUTE)
                    AND %s > DATE_SUB(requested_start, INTERVAL COALESCE(buffer_minutes, 0) MINUTE)
        """,
                (room_no, start_dt, end_dt),
    )
    count = cursor.fetchone()[0]
    conn.close()
    return count


def generate_booking_id(room_no):
    conn = get_connection()
    cursor = conn.cursor()

    while True:
        room_str = str(room_no).zfill(3)
        random_no = str(random.randint(0, 999)).zfill(3)
        booking_id = room_str + random_no

        cursor.execute("SELECT booking_id FROM booking_details WHERE booking_id=%s", (booking_id,))
        old_exists = cursor.fetchone()
        cursor.execute("SELECT booking_id FROM booking_requests WHERE booking_id=%s", (booking_id,))
        new_exists = cursor.fetchone()

        if not old_exists and not new_exists:
            break

    conn.close()
    return booking_id


def _setup_approval_chain_for_requester(cursor, request_id, approval_due_at, requester_role):
    roles = get_approval_flow()
    start_index = 0
    role_in_flow = False
    
    requester_role_lower = (requester_role or "").strip().lower()
    for i, r in enumerate(roles):
        if r.lower() == requester_role_lower:
            start_index = i + 1
            role_in_flow = True
            break
            
    if not role_in_flow and requester_role_lower == "admin":
        start_index = len(roles)
        
    for i, role in enumerate(roles):
        token = secrets.token_urlsafe(32)
        decision = 'Approved' if i < start_index else 'Pending'
        acted_at = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S') if i < start_index else None
        comment = 'Auto-approved based on requester role' if i < start_index else None
        
        if request_id is not None:
            cursor.execute(
                """
                INSERT INTO request_approvals (
                    request_id,
                    approver_role,
                    decision,
                    action_token,
                    token_expires_at,
                    acted_at,
                    comment
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (request_id, role, decision, token, approval_due_at, acted_at, comment),
            )
        
    if start_index < len(roles):
        first_pending_status = f"Pending_{roles[start_index]}"
        next_role = roles[start_index]
    else:
        first_pending_status = "Approved"
        next_role = None
        
    return first_pending_status, next_role


def create_email_log(cursor, request_id, recipient_email, recipient_role, email_type, token=None):
    cursor.execute(
        """
        INSERT INTO email_logs (
            request_id,
            recipient_email,
            recipient_role,
            email_type,
            token
        ) VALUES (%s, %s, %s, %s, %s)
        """,
        (request_id, recipient_email, recipient_role, email_type, token),
    )


def create_booking_request(
    username,
    room_no,
    purpose,
    number_of_persons,
    required_equipment,
    start_datetime,
    end_datetime,
    duration_minutes,
    buffer_minutes=None,
    document_path=None,
    time_slots=None,
    user_comment=None,
):
    requester_department = None
    user = get_user_details(username)
    if user:
        requester_department = (user.get("department") or "").strip() or None

    start_dt = parse_datetime(start_datetime)
    end_dt = parse_datetime(end_datetime)
    if not start_dt or not end_dt or end_dt <= start_dt:
        raise ValueError("Invalid start/end time")

    actual_duration_minutes = int((end_dt - start_dt).total_seconds() // 60)
    if actual_duration_minutes < MIN_BOOKING_MINUTES:
        raise ValueError(f"Minimum booking duration is {MIN_BOOKING_MINUTES} minutes")

    if duration_minutes <= 0:
        duration_minutes = actual_duration_minutes

    if duration_minutes < MIN_BOOKING_MINUTES:
        raise ValueError(f"Minimum booking duration is {MIN_BOOKING_MINUTES} minutes")

    duration_minutes = actual_duration_minutes or duration_minutes
    buffer_minutes = resolve_buffer_minutes(buffer_minutes)

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    hall = get_hall_by_room(room_no)
    if hall and number_of_persons and int(number_of_persons) > int(hall["capacity"]):
        conn.close()
        raise ValueError("Requested persons exceed hall capacity")

    overlap_count = _overlap_count(cursor, room_no, start_dt, end_dt)
    queue_position = overlap_count + 1
    booking_id = generate_booking_id(room_no)
    approval_due_at = datetime.datetime.utcnow() + timedelta(hours=48)

    requester_role = (user.get("role") or "").strip().lower() if user else ""
    first_pending_status, next_role = _setup_approval_chain_for_requester(cursor, None, approval_due_at, requester_role) # Call with None to just get the status
    request_status = "Waitlisted" if queue_position > 1 else first_pending_status

    # Serialize time_slots if provided
    time_slots_json = None
    if time_slots:
        import json
        time_slots_json = json.dumps(time_slots) if isinstance(time_slots, (list, dict)) else str(time_slots)

    cursor.execute(
        """
        INSERT INTO booking_requests (
            booking_id,
            room_no,
            purpose,
            number_of_persons,
            equipment_needs,
            document_path,
            requested_start,
            requested_end,
            duration_minutes,
            buffer_minutes,
            queue_position,
            request_status,
            approval_due_at,
            username,
            requester_department,
            time_slots,
            user_comment
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            booking_id,
            room_no,
            purpose,
            number_of_persons,
            required_equipment,
            document_path,
            start_dt,
            end_dt,
            duration_minutes,
            buffer_minutes,
            queue_position,
            request_status,
            approval_due_at,
            username,
            requester_department,
            time_slots_json,
            user_comment,
        ),
    )
    request_id = cursor.lastrowid

    if request_status != "Waitlisted":
        _setup_approval_chain_for_requester(cursor, request_id, approval_due_at, requester_role)
        if next_role and request_status != "Approved":
            create_email_log(cursor, request_id, None, next_role, "approval_request")
        elif request_status == "Approved":
            cursor.execute("UPDATE booking_requests SET finalized_at=NOW() WHERE request_id=%s", (request_id,))

    conn.commit()
    conn.close()

    result = {
        "request_id": request_id,
        "booking_id": booking_id,
        "queue_position": queue_position,
        "request_status": request_status,
    }

    if request_status == "Waitlisted":
        suggestion = suggest_alternative_slot(room_no, start_dt, duration_minutes, buffer_minutes)
        if suggestion:
            save_suggested_slot(request_id, suggestion["start"], suggestion["end"])
            result["suggested_start"] = suggestion["start"].strftime("%Y-%m-%d %H:%M:%S")
            result["suggested_end"] = suggestion["end"].strftime("%Y-%m-%d %H:%M:%S")

    return result


def update_booking_document(request_id, username, document_path):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE booking_requests SET document_path=%s WHERE request_id=%s AND username=%s",
        (document_path, request_id, username)
    )
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    return affected > 0


def save_suggested_slot(request_id, suggested_start, suggested_end):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE booking_requests
        SET suggested_start=%s, suggested_end=%s
        WHERE request_id=%s
        """,
        (suggested_start, suggested_end, request_id),
    )
    conn.commit()
    conn.close()


def _slot_is_available(cursor, room_no, start_dt, end_dt):
    cursor.execute(
        """
        SELECT 1
        FROM booking_requests
        WHERE room_no=%s
          AND request_status != 'Rejected'
          AND request_status != 'Cancelled'
          AND %s < DATE_ADD(requested_end, INTERVAL COALESCE(buffer_minutes, 0) MINUTE)
          AND %s > DATE_SUB(requested_start, INTERVAL COALESCE(buffer_minutes, 0) MINUTE)
        LIMIT 1
        """,
                (room_no, start_dt, end_dt),
    )
    return cursor.fetchone() is None


def suggest_alternative_slot(room_no, start_datetime, duration_minutes, buffer_minutes=15, lookahead_days=14):
    start_dt = parse_datetime(start_datetime)
    end_limit = start_dt + timedelta(days=lookahead_days)
    step = timedelta(minutes=30)
    duration = timedelta(minutes=duration_minutes + buffer_minutes)

    conn = get_connection()
    cursor = conn.cursor()

    current = start_dt + step
    found = None
    while current < end_limit:
        candidate_end = current + duration
        if _slot_is_available(cursor, room_no, current, candidate_end):
            found = {"start": current, "end": current + timedelta(minutes=duration_minutes)}
            break
        current += step

    conn.close()
    return found


def get_requests_for_user(username):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        """
         SELECT br.request_id, br.booking_id, br.room_no, br.purpose, br.number_of_persons,
             br.equipment_needs, br.requested_start, br.requested_end, br.duration_minutes,
             br.queue_position, br.request_status, br.suggested_start, br.suggested_end,
             br.submitted_at, br.finalized_at, br.time_slots, br.user_comment,
             u.phone AS requester_phone
        FROM booking_requests br
        LEFT JOIN users u ON u.username = br.username
        WHERE br.username=%s
        ORDER BY br.submitted_at DESC
        """,
        (username,),
    )
    rows = cursor.fetchall()
    
    if rows:
        request_ids = [r['request_id'] for r in rows]
        placeholders, params = _build_in_clause(request_ids)
        if placeholders:
            cursor.execute(f"SELECT request_id, approver_role, comment FROM request_approvals WHERE request_id IN ({placeholders}) AND comment IS NOT NULL AND comment != ''", params)
            approvals = cursor.fetchall()
            for r in rows:
                r['all_comments'] = [{'role': a['approver_role'], 'comment': a['comment']} for a in approvals if a['request_id'] == r['request_id']]

    conn.close()
    # Ensure datetime objects are converted to strings for JSON serialization
    for r in rows:
        for k in ('requested_start', 'requested_end', 'submitted_at', 'finalized_at', 'suggested_start', 'suggested_end'):
            if k in r and r[k] is not None:
                try:
                    r[k] = r[k].strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    r[k] = str(r[k])
    return rows


def get_pending_notifications_for_role(role, department=None):
    key = (role or "").lower()
    approver_role = None
    status = None
    
    for r in get_approval_flow():
        if r.lower() == key:
            approver_role = r
            status = f"Pending_{r}"
            break

    if not approver_role:
        return []

    if key == "hod" and not str(department or "").strip():
        return []
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    params = [approver_role, status]
    department_clause = ""
    if key == "hod" and department:
        department_clause = " AND TRIM(LOWER(COALESCE(u.department, ''))) = TRIM(LOWER(%s))"
        params.append(str(department).strip())

    cursor.execute(
        f"""
        SELECT br.request_id, br.booking_id, br.room_no,
               COALESCE(h.hall_name, CONCAT('Hall ', br.room_no)) AS room_name,
               br.purpose, br.number_of_persons,
               br.equipment_needs, br.document_path, br.user_comment,
               br.requested_start, br.requested_end, br.request_status,
               br.username, u.name AS requester_name, u.department AS requester_department, u.phone AS requester_phone,
               ra.decision, ra.comment, br.finalized_at, br.submitted_at
        FROM booking_requests br
        JOIN request_approvals ra ON br.request_id = ra.request_id
        LEFT JOIN users u ON u.username = br.username
        LEFT JOIN halls h ON h.room_no = br.room_no
        WHERE ra.approver_role=%s
            AND ra.decision='Pending'
            AND br.request_status=%s
            {department_clause}
        ORDER BY br.submitted_at ASC
        """,
        tuple(params),
    )
    rows = cursor.fetchall()

    if rows:
        request_ids = [r['request_id'] for r in rows]
        placeholders, params = _build_in_clause(request_ids)
        if placeholders:
            cursor.execute(f"SELECT request_id, approver_role, comment FROM request_approvals WHERE request_id IN ({placeholders}) AND comment IS NOT NULL AND comment != ''", params)
            approvals = cursor.fetchall()
            for r in rows:
                r['all_comments'] = [{'role': a['approver_role'], 'comment': a['comment']} for a in approvals if a['request_id'] == r['request_id']]

    conn.close()
    # Convert datetimes to strings for stable JSON responses
    for r in rows:
        for k in ('requested_start', 'requested_end', 'submitted_at', 'finalized_at'):
            if k in r and r[k] is not None:
                try:
                    r[k] = r[k].strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    r[k] = str(r[k])
    return rows


def _next_status_for(role, decision):
    if decision.lower() == "rejected":
        return "Rejected"

    roles = get_approval_flow()
    role_norm = role.lower()
    for i, r in enumerate(roles):
        if r.lower() == role_norm:
            if i + 1 < len(roles):
                return f"Pending_{roles[i+1]}"
            else:
                return "Approved"
    return "Approved"


def update_notification_stage(notification_id, role, decision):
    # Backward compatibility shim for old route naming.
    return take_approval_action(notification_id, role, decision, comment=None)


def take_approval_action(request_id, role, decision, comment=None, actor_department=None):
    role_norm = (role or "").strip().lower()
    decision_norm = (decision or "").strip().lower()

    if decision_norm not in ("approved", "rejected"):
        return {"ok": False, "message": "decision must be approved or rejected"}

    expected_status = None
    exact_role = role_norm.capitalize()
    for r in get_approval_flow():
        if r.lower() == role_norm:
            expected_status = f"Pending_{r}"
            exact_role = r
            break

    if not expected_status:
        return {"ok": False, "message": "invalid role"}

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT br.*, u.department AS requester_department
        FROM booking_requests br
        LEFT JOIN users u ON u.username = br.username
        WHERE br.request_id=%s
        """,
        (request_id,),
    )
    booking = cursor.fetchone()
    if not booking:
        conn.close()
        return {"ok": False, "message": "request not found"}

    if booking["request_status"] != expected_status:
        conn.close()
        return {"ok": False, "message": "out-of-order action"}

    if role_norm == "hod":
        requester_department = (booking.get("requester_department") or "").strip().lower()
        hod_department = (actor_department or "").strip().lower()
        if not hod_department or requester_department != hod_department:
            conn.close()
            return {"ok": False, "message": "HOD can only process requests from own department"}

    cursor.execute(
        """
        UPDATE request_approvals
        SET decision=%s, comment=%s, acted_at=NOW()
        WHERE request_id=%s AND approver_role=%s AND decision='Pending'
        """,
        (decision_norm.capitalize(), comment, request_id, exact_role),
    )

    if cursor.rowcount == 0:
        conn.close()
        return {"ok": False, "message": "approval already processed"}

    new_status = _next_status_for(role_norm, decision_norm)
    if new_status == "Approved":
        cursor.execute(
            "UPDATE booking_requests SET request_status=%s, finalized_at=NOW() WHERE request_id=%s",
            (new_status, request_id),
        )
    else:
        cursor.execute(
            "UPDATE booking_requests SET request_status=%s WHERE request_id=%s",
            (new_status, request_id),
        )

    next_role = None
    if new_status.startswith("Pending_"):
        next_role = new_status[8:]
        
    if next_role:
        cursor.execute(
            "SELECT action_token FROM request_approvals WHERE request_id=%s AND approver_role=%s",
            (request_id, next_role),
        )
        token_row = cursor.fetchone()
        token = token_row["action_token"] if token_row else None
        create_email_log(cursor, request_id, None, next_role, "approval_request", token)

    conn.commit()
    conn.close()

    return {"ok": True, "message": "request updated", "new_status": new_status}


def process_one_click_approval(token, decision, comment=None):
    decision_norm = (decision or "").strip().lower()
    if decision_norm not in ("approved", "rejected"):
        return {"ok": False, "message": "invalid decision"}

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        """
        SELECT request_id, approver_role, token_expires_at, decision
        FROM request_approvals
        WHERE action_token=%s
        """,
        (token,),
    )
    row = cursor.fetchone()
    if not row:
        conn.close()
        return {"ok": False, "message": "invalid token"}

    if row["decision"] != "Pending":
        conn.close()
        return {"ok": False, "message": "token already used"}

    if row["token_expires_at"] and row["token_expires_at"] < datetime.datetime.utcnow():
        conn.close()
        return {"ok": False, "message": "token expired"}

    cursor.execute(
        "UPDATE email_logs SET clicked_at=NOW(), status='clicked' WHERE token=%s",
        (token,),
    )
    conn.commit()

    # For HOD one-click approvals, resolve department from the requester
    # (the email was already sent only to the HOD of the same department)
    actor_department = None
    if row["approver_role"].upper() == "HOD":
        cursor2 = conn.cursor(dictionary=True)
        cursor2.execute(
            """
            SELECT u.department
            FROM booking_requests br
            JOIN users u ON u.username = br.username
            WHERE br.request_id=%s
            LIMIT 1
            """,
            (row["request_id"],),
        )
        dept_row = cursor2.fetchone()
        if dept_row:
            actor_department = dept_row["department"]

    conn.close()

    result = take_approval_action(row["request_id"], row["approver_role"], decision_norm, comment, actor_department)
    if isinstance(result, dict):
        result["request_id"] = row["request_id"]
        result["approver_role"] = row["approver_role"]
    return result


def accept_suggested_slot(request_id, username):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        """
        SELECT * FROM booking_requests
        WHERE request_id=%s AND username=%s
        """,
        (request_id, username),
    )
    row = cursor.fetchone()

    if not row:
        conn.close()
        return {"ok": False, "message": "request not found"}

    if not row["suggested_start"] or not row["suggested_end"]:
        conn.close()
        return {"ok": False, "message": "no suggested slot available"}

    start_dt = row["suggested_start"]
    end_dt = row["suggested_end"]
    overlap_count = _overlap_count(cursor, row["room_no"], start_dt, end_dt)
    queue_position = overlap_count + 1

    if queue_position > 1:
        conn.close()
        return {"ok": False, "message": "suggested slot is no longer available"}

    approval_due_at = datetime.datetime.utcnow() + timedelta(hours=48)
    
    user = get_user_details(username)
    requester_role = (user.get("role") or "").strip().lower() if user else ""
    first_pending_status, next_role = _setup_approval_chain_for_requester(cursor, None, approval_due_at, requester_role)
    
    cursor.execute(
        """
        UPDATE booking_requests
        SET requested_start=%s,
            requested_end=%s,
            suggested_start=NULL,
            suggested_end=NULL,
            queue_position=1,
            request_status=%s,
            approval_due_at=%s
        WHERE request_id=%s
        """,
        (start_dt, end_dt, first_pending_status, approval_due_at, request_id),
    )

    cursor.execute("DELETE FROM request_approvals WHERE request_id=%s", (request_id,))
    _setup_approval_chain_for_requester(cursor, request_id, approval_due_at, requester_role)
    
    if next_role and first_pending_status != "Approved":
        create_email_log(cursor, request_id, None, next_role, "approval_request")
    elif first_pending_status == "Approved":
        cursor.execute("UPDATE booking_requests SET finalized_at=NOW() WHERE request_id=%s", (request_id,))

    conn.commit()
    conn.close()
    return {"ok": True, "message": "slot accepted and resubmitted"}


def expire_stale_requests():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE booking_requests
        SET request_status='Expired'
        WHERE request_status IN (%s, %s, %s)
          AND approval_due_at IS NOT NULL
          AND approval_due_at < UTC_TIMESTAMP()
        """,
        ("Pending_HOD", "Pending_Principal", "Pending_Secretary"),
    )
    updated = cursor.rowcount
    conn.commit()
    conn.close()
    return updated


def override_booking_status(request_id, new_status, reason=None, actor_role='admin'):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE booking_requests SET request_status=%s, updated_at=NOW() WHERE request_id=%s",
        (new_status, request_id),
    )
    changed = cursor.rowcount

    if reason:
        role_key = str(actor_role or 'admin').strip().lower()
        actor_label = {
            'admin': 'Admin',
            'hod': 'HOD',
            'principal': 'Principal',
            'secretary': 'Secretary',
        }.get(role_key, 'Admin')

        # Logging should never block override action if email_logs constraints differ.
        try:
            cursor.execute(
                """
                INSERT INTO email_logs (request_id, recipient_role, email_type, status)
                VALUES (%s, %s, %s, 'recorded')
                """,
                (request_id, actor_label, 'override'),
            )
        except Exception:
            pass

    conn.commit()
    conn.close()
    return changed > 0


def get_admin_analytics(filters=None):
    filters = filters or {}
    data = get_approver_analytics("admin", "", filters=filters)

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT COUNT(*) AS total_active_users FROM users")
    data["total_active_users"] = int((cursor.fetchone() or {}).get("total_active_users") or 0)

    cursor.execute(
        """
        SELECT COALESCE(NULLIF(TRIM(role), ''), 'unknown') AS role,
               COUNT(*) AS user_count
        FROM users
        GROUP BY COALESCE(NULLIF(TRIM(role), ''), 'unknown')
        ORDER BY user_count DESC, role ASC
        """
    )
    data["role_breakdown"] = cursor.fetchall()

    cursor.execute(
        """
        SELECT *
        FROM (
            SELECT br.submitted_at AS event_time,
                   COALESCE(u.name, br.username, 'Unknown') AS username,
                   'Booking Created' AS action,
                   br.booking_id,
                   NULL AS previous_status,
                   br.request_status AS updated_status
            FROM booking_requests br
            LEFT JOIN users u ON u.username = br.username

            UNION ALL

            SELECT COALESCE(ra.acted_at, ra.created_at) AS event_time,
                   UPPER(ra.approver_role) AS username,
                   CONCAT('Approval ', ra.decision) AS action,
                   br.booking_id,
                   'Pending' AS previous_status,
                   ra.decision AS updated_status
            FROM request_approvals ra
            LEFT JOIN booking_requests br ON br.request_id = ra.request_id
            WHERE ra.decision <> 'Pending'

            UNION ALL

            SELECT br.updated_at AS event_time,
                   COALESCE(u.name, br.username, 'Unknown') AS username,
                   'Waiting List Updated' AS action,
                   br.booking_id,
                   NULL AS previous_status,
                   br.request_status AS updated_status
            FROM booking_requests br
            LEFT JOIN users u ON u.username = br.username
            WHERE br.request_status = 'Waitlisted' OR br.queue_position > 1

            UNION ALL

            SELECT el.sent_at AS event_time,
                   COALESCE(el.recipient_email, el.recipient_role, 'System') AS username,
                   CONCAT('Email ', COALESCE(el.email_type, 'notification')) AS action,
                   br.booking_id,
                   NULL AS previous_status,
                   el.status AS updated_status
            FROM email_logs el
            LEFT JOIN booking_requests br ON br.request_id = el.request_id

            UNION ALL

            SELECT loc.created_at AS event_time,
                   loc.username,
                   'OTP Verification' AS action,
                   NULL AS booking_id,
                   NULL AS previous_status,
                   CASE
                       WHEN loc.consumed_at IS NULL THEN 'Issued'
                       ELSE 'Consumed'
                   END AS updated_status
            FROM login_otp_challenges loc
        ) audit
        WHERE event_time IS NOT NULL
        ORDER BY event_time DESC
        LIMIT 24
        """
    )
    data["system_logs"] = cursor.fetchall()

    conn.close()
    return data


def get_approver_analytics(role, department=None, filters=None):
    """Return live approver analytics.

    Department charts are driven from distinct departments already present in
    users or booking requests, so newly added departments appear automatically.
    """
    role_norm = (role or "").strip().lower()
    filters = filters or {}
    department_filter = (filters.get("department") or "").strip()
    room_filter = filters.get("room_no")
    status_filter = (filters.get("status") or "").strip()
    role_filter = (filters.get("user_role") or "").strip()
    time_slot_filter = filters.get("time_slot")
    date_from = (filters.get("date_from") or "").strip()
    date_to = (filters.get("date_to") or "").strip()

    pending_statuses = tuple(f"Pending_{r}" for r in get_approval_flow())
    active_statuses = pending_statuses + ("Approved", "Waitlisted")
    normalized_status = status_filter.lower()

    def department_expr(alias="br", user_alias="u"):
        return (
            f"COALESCE(NULLIF(TRIM({alias}.requester_department), ''), "
            f"NULLIF(TRIM({user_alias}.department), ''), 'Unknown')"
        )

    def booking_filter_clause(alias="br", user_alias="u", prefix="WHERE"):
        clauses = []
        params = []
        if date_from:
            clauses.append(f"{alias}.requested_start >= %s")
            params.append(f"{date_from} 00:00:00")
        if date_to:
            clauses.append(f"{alias}.requested_start < DATE_ADD(%s, INTERVAL 1 DAY)")
            params.append(date_to)
        if room_filter:
            clauses.append(f"{alias}.room_no = %s")
            params.append(int(room_filter))
        if time_slot_filter not in (None, ""):
            clauses.append(f"HOUR({alias}.requested_start) = %s")
            params.append(int(time_slot_filter))
        if status_filter:
            if normalized_status == "pending":
                placeholders = ", ".join(["%s"] * len(pending_statuses))
                clauses.append(f"{alias}.request_status IN ({placeholders})")
                params.extend(pending_statuses)
            else:
                clauses.append(f"{alias}.request_status = %s")
                params.append(status_filter)
        if department_filter:
            clauses.append(
                f"TRIM(LOWER({department_expr(alias, user_alias)})) = TRIM(LOWER(%s))"
            )
            params.append(department_filter)
        if role_filter:
            clauses.append(f"TRIM(LOWER({user_alias}.role)) = TRIM(LOWER(%s))")
            params.append(role_filter)

        if not clauses:
            return "", params
        return f"{prefix} " + " AND ".join(clauses), params

    def scoped_booking_subquery(extra_where=None):
        filter_sql, params = booking_filter_clause("br", "u", "WHERE")
        where_sql = filter_sql
        if extra_where:
            if where_sql:
                where_sql += f" AND {extra_where}"
            else:
                where_sql = f"WHERE {extra_where}"
        return (
            f"""
            SELECT br.*,
                   {department_expr("br", "u")} AS department_name,
                   COALESCE(u.name, br.username, 'Unknown') AS requester_name,
                   u.role AS requester_role
            FROM booking_requests br
            LEFT JOIN users u ON u.username = br.username
            {where_sql}
            """,
            params,
        )

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT department
        FROM (
            SELECT NULLIF(TRIM(department), '') AS department
            FROM users
            UNION
            SELECT COALESCE(
                NULLIF(TRIM(br.requester_department), ''),
                NULLIF(TRIM(u.department), '')
            ) AS department
            FROM booking_requests br
            LEFT JOIN users u ON u.username = br.username
        ) d
        WHERE department IS NOT NULL AND department <> ''
        GROUP BY department
        ORDER BY department ASC
        """
    )
    available_departments = cursor.fetchall()

    cursor.execute(
        """
        SELECT room_no, COALESCE(hall_name, CONCAT('Hall ', room_no)) AS hall_name
        FROM halls
        WHERE is_active = TRUE
        ORDER BY room_no ASC
        """
    )
    available_rooms = cursor.fetchall()

    cursor.execute(
        """
        SELECT COALESCE(NULLIF(TRIM(role), ''), 'unknown') AS role
        FROM users
        GROUP BY COALESCE(NULLIF(TRIM(role), ''), 'unknown')
        ORDER BY role ASC
        """
    )
    available_roles = cursor.fetchall()

    status_filter_sql, status_params = booking_filter_clause("br", "u", "WHERE")
    cursor.execute(
        f"""
        SELECT br.request_status AS status, COUNT(*) AS count
        FROM booking_requests br
        LEFT JOIN users u ON u.username = br.username
        {status_filter_sql}
        GROUP BY br.request_status
        ORDER BY count DESC, status ASC
        """,
        tuple(status_params),
    )
    status_breakdown = cursor.fetchall()

    status_lookup = {
        (row.get("status") or "Unknown"): int(row.get("count") or 0)
        for row in status_breakdown
    }
    total_bookings = sum(status_lookup.values())
    approved_count = status_lookup.get("Approved", 0)
    rejected_count = status_lookup.get("Rejected", 0)
    pending_count = sum(status_lookup.get(status, 0) for status in pending_statuses)
    waitlisted_count = status_lookup.get("Waitlisted", 0)

    cursor.execute("SELECT COUNT(*) AS total_rooms FROM halls WHERE is_active = TRUE")
    total_rooms = int((cursor.fetchone() or {}).get("total_rooms") or 0)

    scoped_sql, scoped_params = scoped_booking_subquery()
    department_where = ""
    department_params = []
    if department_filter:
        department_where = "WHERE TRIM(LOWER(d.department)) = TRIM(LOWER(%s))"
        department_params.append(department_filter)

    cursor.execute(
        f"""
        SELECT d.department,
               COUNT(sb.request_id) AS total_requests,
               COALESCE(SUM(CASE WHEN sb.request_status = 'Approved' THEN 1 ELSE 0 END), 0) AS approved_count,
               COALESCE(SUM(CASE WHEN sb.request_status = 'Rejected' THEN 1 ELSE 0 END), 0) AS rejected_count,
               COALESCE(SUM(CASE WHEN sb.request_status IN ('Pending_HOD', 'Pending_Principal', 'Pending_Secretary') THEN 1 ELSE 0 END), 0) AS pending_count,
               COALESCE(SUM(CASE WHEN sb.request_status = 'Waitlisted' THEN 1 ELSE 0 END), 0) AS waitlisted_count,
               ROUND(COALESCE(SUM(CASE WHEN sb.request_status = 'Approved' THEN sb.duration_minutes ELSE 0 END), 0) / 60, 1) AS usage_hours,
               ROUND(
                   COALESCE(SUM(CASE WHEN sb.request_status = 'Approved' THEN 1 ELSE 0 END), 0)
                   / NULLIF(COUNT(sb.request_id), 0) * 100,
                   1
               ) AS approval_rate
        FROM (
            SELECT department
            FROM (
                SELECT NULLIF(TRIM(department), '') AS department
                FROM users
                UNION
                SELECT COALESCE(
                    NULLIF(TRIM(br.requester_department), ''),
                    NULLIF(TRIM(u.department), '')
                ) AS department
                FROM booking_requests br
                LEFT JOIN users u ON u.username = br.username
            ) raw_departments
            WHERE department IS NOT NULL AND department <> ''
            GROUP BY department
        ) d
        LEFT JOIN ({scoped_sql}) sb
          ON TRIM(LOWER(sb.department_name)) = TRIM(LOWER(d.department))
        {department_where}
        GROUP BY d.department
        ORDER BY total_requests DESC, approved_count DESC, d.department ASC
        """,
        tuple(scoped_params + department_params),
    )
    department_usage = cursor.fetchall()

    room_sql, room_params = scoped_booking_subquery()
    room_where = "WHERE h.is_active = TRUE"
    room_where_params = []
    if room_filter:
        room_where += " AND h.room_no = %s"
        room_where_params.append(int(room_filter))

    cursor.execute(
        f"""
        SELECT h.room_no,
               COALESCE(h.hall_name, CONCAT('Hall ', h.room_no)) AS hall_name,
               h.capacity,
               COUNT(sb.request_id) AS booking_count,
               COALESCE(SUM(CASE WHEN sb.request_status = 'Approved' THEN 1 ELSE 0 END), 0) AS approved_count,
               ROUND(COALESCE(SUM(CASE WHEN sb.request_status = 'Approved' THEN sb.duration_minutes ELSE 0 END), 0) / 60, 1) AS usage_hours,
               ROUND(AVG(CASE WHEN sb.request_status = 'Approved' THEN sb.number_of_persons ELSE NULL END), 1) AS avg_occupancy,
               COALESCE(SUM(CASE WHEN sb.request_status = 'Waitlisted' OR sb.queue_position > 1 THEN 1 ELSE 0 END), 0) AS conflict_count
        FROM halls h
        LEFT JOIN ({room_sql}) sb ON sb.room_no = h.room_no
        {room_where}
        GROUP BY h.room_no, h.hall_name, h.capacity
        ORDER BY approved_count DESC, booking_count DESC, h.room_no ASC
        """,
        tuple(room_params + room_where_params),
    )
    hall_usage = cursor.fetchall()

    max_usage_hours = max(
        [float(row.get("usage_hours") or 0) for row in hall_usage] or [0]
    )
    for row in hall_usage:
        usage_hours = float(row.get("usage_hours") or 0)
        utilization = round((usage_hours / max_usage_hours) * 100, 1) if max_usage_hours else 0
        row["utilization_percent"] = utilization
        row["availability_percent"] = round(100 - utilization, 1)

    trend_sql, trend_params = booking_filter_clause("br", "u", "WHERE")
    if not date_from and not date_to:
        trend_sql = f"{trend_sql} AND br.submitted_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)" if trend_sql else "WHERE br.submitted_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)"
    cursor.execute(
        f"""
        SELECT DATE(br.submitted_at) AS date_label,
               COUNT(*) AS bookings
        FROM booking_requests br
        LEFT JOIN users u ON u.username = br.username
        {trend_sql}
        GROUP BY DATE(br.submitted_at)
        ORDER BY date_label ASC
        """,
        tuple(trend_params),
    )
    booking_trend = cursor.fetchall()

    monthly_sql, monthly_params = booking_filter_clause("br", "u", "WHERE")
    if not date_from and not date_to:
        monthly_sql = f"{monthly_sql} AND br.submitted_at >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH)" if monthly_sql else "WHERE br.submitted_at >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH)"
    cursor.execute(
        f"""
        SELECT DATE_FORMAT(br.submitted_at, '%%Y-%%m') AS month,
               COUNT(*) AS bookings
        FROM booking_requests br
        LEFT JOIN users u ON u.username = br.username
        {monthly_sql}
        GROUP BY DATE_FORMAT(br.submitted_at, '%%Y-%%m')
        ORDER BY month ASC
        """,
        tuple(monthly_params),
    )
    monthly_trend = cursor.fetchall()

    peak_sql, peak_params = booking_filter_clause("br", "u", "WHERE")
    cursor.execute(
        f"""
        SELECT HOUR(br.requested_start) AS hour_of_day,
               COUNT(*) AS bookings
        FROM booking_requests br
        LEFT JOIN users u ON u.username = br.username
        {peak_sql}
        GROUP BY HOUR(br.requested_start)
        ORDER BY bookings DESC, hour_of_day ASC
        """,
        tuple(peak_params),
    )
    peak_hours = cursor.fetchall()

    heatmap_sql, heatmap_params = booking_filter_clause("br", "u", "WHERE")
    if not status_filter:
        placeholders = ", ".join(["%s"] * len(active_statuses))
        heatmap_sql = (
            f"{heatmap_sql} AND br.request_status IN ({placeholders})"
            if heatmap_sql
            else f"WHERE br.request_status IN ({placeholders})"
        )
        heatmap_params.extend(active_statuses)
    cursor.execute(
        f"""
        SELECT WEEKDAY(br.requested_start) AS day_index,
               DAYNAME(br.requested_start) AS day_name,
               HOUR(br.requested_start) AS hour_of_day,
               COUNT(*) AS bookings
        FROM booking_requests br
        LEFT JOIN users u ON u.username = br.username
        {heatmap_sql}
        GROUP BY WEEKDAY(br.requested_start), DAYNAME(br.requested_start), HOUR(br.requested_start)
        ORDER BY day_index ASC, hour_of_day ASC
        """,
        tuple(heatmap_params),
    )
    time_slot_heatmap = cursor.fetchall()

    avg_sql, avg_params = booking_filter_clause("br", "u", "WHERE")
    avg_sql = (
        f"{avg_sql} AND br.request_status = 'Approved' AND br.finalized_at IS NOT NULL"
        if avg_sql
        else "WHERE br.request_status = 'Approved' AND br.finalized_at IS NOT NULL"
    )
    cursor.execute(
        f"""
        SELECT ROUND(AVG(TIMESTAMPDIFF(HOUR, br.submitted_at, br.finalized_at)), 1)
               AS avg_hours
        FROM booking_requests br
        LEFT JOIN users u ON u.username = br.username
        {avg_sql}
        """,
        tuple(avg_params),
    )
    avg_row = cursor.fetchone()
    avg_turnaround_hours = float(avg_row.get("avg_hours") or 0) if avg_row else 0

    wait_sql, wait_params = booking_filter_clause("br", "u", "WHERE")
    wait_sql = (
        f"{wait_sql} AND br.request_status = 'Waitlisted'"
        if wait_sql
        else "WHERE br.request_status = 'Waitlisted'"
    )
    cursor.execute(
        f"""
        SELECT ROUND(AVG(TIMESTAMPDIFF(MINUTE, br.submitted_at, NOW())), 0) AS avg_minutes
        FROM booking_requests br
        LEFT JOIN users u ON u.username = br.username
        {wait_sql}
        """,
        tuple(wait_params),
    )
    wait_row = cursor.fetchone()
    avg_wait_minutes = int((wait_row or {}).get("avg_minutes") or 0)

    waiting_dept_sql, waiting_dept_params = scoped_booking_subquery("br.request_status = 'Waitlisted'")
    cursor.execute(
        f"""
        SELECT department_name AS department,
               COUNT(*) AS waiting_count
        FROM ({waiting_dept_sql}) waiting
        GROUP BY department_name
        ORDER BY waiting_count DESC, department_name ASC
        """,
        tuple(waiting_dept_params),
    )
    waiting_by_department = cursor.fetchall()

    conflict_sql, conflict_params = booking_filter_clause("br", "u", "WHERE")
    conflict_sql = (
        f"{conflict_sql} AND (br.request_status = 'Waitlisted' OR br.queue_position > 1)"
        if conflict_sql
        else "WHERE br.request_status = 'Waitlisted' OR br.queue_position > 1"
    )
    cursor.execute(
        f"""
        SELECT br.room_no,
               COALESCE(h.hall_name, CONCAT('Hall ', br.room_no)) AS hall_name,
               DATE(br.requested_start) AS slot_date,
               HOUR(br.requested_start) AS hour_of_day,
               COUNT(*) AS conflict_count
        FROM booking_requests br
        LEFT JOIN users u ON u.username = br.username
        LEFT JOIN halls h ON h.room_no = br.room_no
        {conflict_sql}
        GROUP BY br.room_no, h.hall_name, DATE(br.requested_start), HOUR(br.requested_start)
        ORDER BY conflict_count DESC, slot_date DESC
        LIMIT 8
        """,
        tuple(conflict_params),
    )
    conflicting_slots = cursor.fetchall()

    requester_sql, requester_params = booking_filter_clause("br", "u", "WHERE")
    cursor.execute(
        f"""
        SELECT br.username,
               COALESCE(u.name, br.username, 'Unknown') AS name,
               {department_expr("br", "u")} AS department,
               COUNT(*) AS booking_count,
               COALESCE(SUM(CASE WHEN br.request_status = 'Approved' THEN 1 ELSE 0 END), 0) AS approved_count,
               ROUND(
                   COALESCE(SUM(CASE WHEN br.request_status = 'Approved' THEN 1 ELSE 0 END), 0)
                   / NULLIF(COUNT(*), 0) * 100,
                   1
               ) AS approval_success_rate
        FROM booking_requests br
        LEFT JOIN users u ON u.username = br.username
        {requester_sql}
        GROUP BY br.username, u.name, {department_expr("br", "u")}
        ORDER BY booking_count DESC, approved_count DESC
        LIMIT 8
        """,
        tuple(requester_params),
    )
    top_requesters = cursor.fetchall()

    recent_sql, recent_params = booking_filter_clause("br", "u", "WHERE")
    cursor.execute(
        f"""
        SELECT br.request_id,
               br.booking_id,
               br.room_no,
               COALESCE(h.hall_name, CONCAT('Hall ', br.room_no)) AS hall_name,
               br.purpose,
               br.request_status,
               br.submitted_at,
               br.updated_at,
               br.requested_start,
               br.requested_end,
               COALESCE(u.name, br.username, 'Unknown') AS requester_name,
               {department_expr("br", "u")} AS requester_department
        FROM booking_requests br
        LEFT JOIN users u ON u.username = br.username
        LEFT JOIN halls h ON h.room_no = br.room_no
        {recent_sql}
        ORDER BY COALESCE(br.updated_at, br.submitted_at) DESC
        LIMIT 8
        """,
        tuple(recent_params),
    )
    recent_activity = cursor.fetchall()

    # Approval / Rejection action log
    log_sql, log_params = booking_filter_clause("br", "u", "WHERE")
    log_where = (
        f"{log_sql} AND ra.decision IN ('Approved', 'Rejected') AND ra.acted_at IS NOT NULL"
        if log_sql
        else "WHERE ra.decision IN ('Approved', 'Rejected') AND ra.acted_at IS NOT NULL"
    )
    cursor.execute(
        f"""
        SELECT ra.approval_id,
               ra.approver_role,
               ra.decision,
               ra.comment,
               ra.acted_at,
               br.booking_id,
               br.room_no,
               COALESCE(h.hall_name, CONCAT('Hall ', br.room_no)) AS hall_name,
               br.purpose,
               br.requested_start,
               br.request_status,
               COALESCE(u.name, br.username, 'Unknown') AS requester_name,
               {department_expr('br', 'u')} AS requester_department
        FROM request_approvals ra
        JOIN booking_requests br ON br.request_id = ra.request_id
        LEFT JOIN users u ON u.username = br.username
        LEFT JOIN halls h ON h.room_no = br.room_no
        {log_where}
        ORDER BY ra.acted_at DESC
        LIMIT 100
        """,
        tuple(log_params),
    )
    approval_logs = cursor.fetchall()

    conn.close()

    most_booked_room = hall_usage[0] if hall_usage else None
    top_department = department_usage[0] if department_usage else None

    approval_summary = [
        {"status": "Approved", "count": approved_count},
        {"status": "Rejected", "count": rejected_count},
        {"status": "Pending", "count": pending_count},
        {"status": "Waitlisted", "count": waitlisted_count},
        {"status": "Cancelled", "count": status_lookup.get("Cancelled", 0)},
        {"status": "Expired", "count": status_lookup.get("Expired", 0)},
    ]

    return {
        "role": role_norm,
        "current_department": (department or "").strip(),
        "filters": filters,
        "available_departments": available_departments,
        "available_rooms": available_rooms,
        "available_roles": available_roles,
        "total_bookings": total_bookings,
        "approved_count": approved_count,
        "rejected_count": rejected_count,
        "pending_count": pending_count,
        "waitlisted_count": waitlisted_count,
        "total_rooms": total_rooms,
        "most_booked_room": most_booked_room,
        "top_department": top_department,
        "avg_turnaround_hours": avg_turnaround_hours,
        "avg_wait_minutes": avg_wait_minutes,
        "status_breakdown": status_breakdown,
        "approval_summary": approval_summary,
        "department_usage": department_usage,
        "peak_hours": peak_hours,
        "hall_usage": hall_usage,
        "booking_trend": booking_trend,
        "monthly_trend": monthly_trend,
        "time_slot_heatmap": time_slot_heatmap,
        "waiting_by_department": waiting_by_department,
        "conflicting_slots": conflicting_slots,
        "top_requesters": top_requesters,
        "recent_activity": recent_activity,
        "approval_logs": approval_logs,
    }


def create_notification(
    event_type,
    purpose,
    name,
    role,
    username,
    booking_id=None,
    start_datetime=None,
    end_datetime=None,
):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO notifications (
            event_type,
            booking_id,
            purpose,
            start_time,
            end_time,
            name,
            role,
            username,
            current_stage,
            HODstatus,
            pstatus,
            sstatus
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            event_type,
            booking_id,
            purpose,
            start_datetime,
            end_datetime,
            name,
            role,
            username,
            "HOD",
            "pending",
            "pending",
            "pending",
        ),
    )

    notification_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return notification_id


def create_signup_notification(username, name, role, purpose="New signup request"):
    return create_notification(
        event_type="signup",
        booking_id=None,
        purpose=purpose,
        start_datetime=None,
        end_datetime=None,
        name=name,
        role=role,
        username=username,
    )


def create_booking_notification(booking_id, purpose, start_datetime, end_datetime, name, role, username):
    return create_notification(
        event_type="booking",
        booking_id=booking_id,
        purpose=purpose,
        start_datetime=start_datetime,
        end_datetime=end_datetime,
        name=name,
        role=role,
        username=username,
    )


def _initialize_default_config():
    
    """Initialize default configuration values if they don't exist."""
    default_configs = {
        "app_title": "Meeting Hall System",
        "app_brand": "DSCE",
        "app_navbar_brand": "📅 MeetBook",
        "app_logo_path": "/static/logo.png",
        "admin_username": "admin",
        "admin_password": "admin123",  # Should be hashed in production
        "admin_otp_email": "slganeshkarthik@gmail.com",
        "organization_name": "DSCE",
        "default_buffer_minutes": str(DEFAULT_BUFFER_MINUTES),
        "system_email": os.environ.get("MAIL_USERNAME", "booking@dsce.edu"),
        "smtp_password": os.environ.get("MAIL_PASSWORD", ""),
    }
    
    conn = get_connection()
    cursor = conn.cursor()
    
    for key, value in default_configs.items():
        cursor.execute(
            """
            INSERT IGNORE INTO app_config (config_key, config_value, description)
            VALUES (%s, %s, %s)
            """,
            (key, value, f"Configuration for {key}"),
        )
    
    conn.commit()
    conn.close()


def get_config(config_key):
    """Get a single configuration value."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT config_value FROM app_config WHERE config_key=%s",
        (config_key,),
    )
    row = cursor.fetchone()
    conn.close()
    
    return row[0] if row else None


def get_all_config():
    """Get all configuration values as a dictionary."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT config_key, config_value FROM app_config")
    rows = cursor.fetchall()
    conn.close()
    
    return {row["config_key"]: row["config_value"] for row in rows}


def set_config(config_key, config_value, description=None):
    """Set or update a configuration value."""
    conn = get_connection()
    cursor = conn.cursor()
    
    if description is None:
        description = f"Configuration for {config_key}"
    
    cursor.execute(
        """
        INSERT INTO app_config (config_key, config_value, description)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE
            config_value=VALUES(config_value),
            description=VALUES(description)
        """,
        (config_key, config_value, description),
    )
    conn.commit()
    conn.close()
    return True


def create_admin_alert(category, severity, title, message, username=None, endpoint=None, status_code=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO admin_alerts (category, severity, title, message, username, endpoint, status_code)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (category, severity, title, message, username, endpoint, status_code),
    )
    conn.commit()
    conn.close()


def get_recent_admin_alerts(limit=25, unread_only=False):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    limit_value = int(limit)
    if unread_only:
        cursor.execute(
            """
            SELECT alert_id, category, severity, title, message, username, endpoint, status_code, is_read, created_at
            FROM admin_alerts
            WHERE is_read=FALSE
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (limit_value,),
        )
    else:
        cursor.execute(
            """
            SELECT alert_id, category, severity, title, message, username, endpoint, status_code, is_read, created_at
            FROM admin_alerts
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (limit_value,),
        )
    rows = cursor.fetchall()
    conn.close()
    return rows


def mark_admin_alerts_as_read(alert_ids):
    placeholders, params = _build_in_clause(alert_ids)
    if not placeholders:
        return 0

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        f"UPDATE admin_alerts SET is_read=TRUE WHERE alert_id IN ({placeholders})",
        params,
    )
    updated = cursor.rowcount
    conn.commit()
    conn.close()
    return updated


def initialize_all():
    init_db()
