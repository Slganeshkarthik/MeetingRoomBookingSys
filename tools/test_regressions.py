from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash


ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "backend" / "app.py").read_text(encoding="utf-8")
DB = (ROOT / "dataBase" / "db_init.py").read_text(encoding="utf-8")


def assert_true(condition, message):
    if not condition:
        raise AssertionError(message)


def test_settings_otp_uses_challenge_schema():
    assert_true(
        "secrets.randbelow(100000, 999999)" not in APP,
        "settings OTP must not call secrets.randbelow with two args",
    )
    assert_true(
        "WHERE id = %s" not in APP,
        "login_otp_challenges is keyed by challenge_id, not id",
    )
    assert_true(
        "create_login_otp_challenge(username, role, user['email'])" in APP,
        "settings OTP should create a full login_otp_challenges row",
    )


def test_password_updates_use_werkzeug_hashes():
    hashed = generate_password_hash("newpass123")
    assert_true(check_password_hash(hashed, "newpass123"), "Werkzeug password hash should validate")
    assert_true("bcrypt.hashpw" not in DB, "password updates should not store raw bcrypt hashes")
    assert_true("generate_password_hash(new_password)" in DB, "password updates should use Werkzeug hashes")


def test_contact_form_escapes_html():
    assert_true("html.escape(sender_name" in APP, "contact HTML email should escape sender name")
    assert_true("html.escape(message_body" in APP, "contact HTML email should escape message body")
    assert_true("TRUST_PROXY_HEADERS" in APP, "contact rate limit should not blindly trust X-Forwarded-For")


def test_env_mail_config_syncs_to_admin_config():
    assert_true("env_overrides" in DB, "environment mail settings should sync into app_config")
    assert_true("MAIL_DEFAULT_SENDER" in DB, "system_email should prefer MAIL_DEFAULT_SENDER when present")
    assert_true("ADMIN_OTP_EMAIL" in DB, "admin OTP email should sync from environment when present")


def test_multi_slot_booking_creates_real_rows():
    assert_true('"bookings": created_results' in APP, "multi-slot create response should expose all created bookings")
    assert_true('"booking_count": len(created_results)' in APP, "multi-slot create response should report count")
    assert_true("time_slots=[slot] if normalized_slots else time_slots" in APP, "each selected slot should create its own request")
    assert_true("request_group_id" in APP, "multi-slot bookings should assign a request_group_id")
    assert_true("request_group_id" in DB, "booking_requests should store request_group_id")


def test_admin_log_page_exists():
    admin_logs = ROOT / "frontend" / "templates" / "admin_logs.html"
    assert_true(admin_logs.exists(), "admin log page template should exist")
    html = admin_logs.read_text(encoding="utf-8")
    assert_true("/api/admin/logs/email" in html, "admin logs page should load email logs")
    assert_true("/api/admin/logs/otp" in html, "admin logs page should load OTP logs")
    assert_true("@app.route('/api/admin/logs/email'" in APP, "email log API should exist")
    assert_true("@app.route('/api/admin/logs/otp'" in APP, "OTP log API should exist")
    assert_true("otp_hash" not in html, "OTP hashes should not be rendered by the logs page")


if __name__ == "__main__":
    for test in (
        test_settings_otp_uses_challenge_schema,
        test_password_updates_use_werkzeug_hashes,
        test_contact_form_escapes_html,
        test_env_mail_config_syncs_to_admin_config,
        test_multi_slot_booking_creates_real_rows,
        test_admin_log_page_exists,
    ):
        test()
    print("Regression checks passed.")
