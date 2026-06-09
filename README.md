# 🏢 Meeting Room Booking System

A full-featured **web-based meeting room reservation system** built with Flask and MySQL. Supports role-based access control, multi-stage approval workflows, OTP-secured logins, email notifications, and a rich admin dashboard — deployable locally or on the cloud via Docker/Render.

---

## ✨ Features

### 🔐 Role-Based Access Control
| Role | Description |
|------|-------------|
| **Admin** | Full system control — manage users, halls, approval flow, config, and analytics |
| **HOD / Principal / Secretary** | Approver roles — review and approve/reject booking requests |
| **Faculty / Staff / Student** | Requesters — submit and track room booking requests |

### 📅 Booking & Approval
- **Multi-time-slot bookings** with conflict detection
- **Configurable approval workflow** (e.g., HOD → Principal → Secretary)
- **One-click email approval** links for approvers
- **Alternative slot suggestion** when a slot is rejected
- **Auto-expiry** of stale/pending requests via background scheduler

### 🔒 Security
- **OTP-secured login** for privileged roles (Admin, HOD, Principal, Secretary)
- **Bcrypt** password hashing
- **CSRF protection** on all forms
- **Login failure tracking** with admin email alerts on repeated failures
- **Session-based authentication** with role verification on every request

### 📧 Email Notifications
- OTP delivery for secure login
- Booking status updates (approved, rejected, alternative suggested)
- Admin security alert emails
- Supports **SendGrid** (recommended for cloud) or **SMTP/Gmail** fallback

### 🖥️ Dashboards
- **Admin Dashboard** — booking overview, user management, system health, analytics
- **Approver Dashboard** — pending approvals, analytics, booking history
- **Requester Dashboard** — booking submission, status tracking, history

### 🏛️ Hall Management
- Add, edit, and delete meeting halls
- Gallery view for available rooms
- Per-hall capacity, location, and feature configuration

### ⚙️ System Configuration
- SMTP settings editable from the admin UI
- Approval flow customization
- Buffer time between bookings
- Logo upload and system branding

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11, Flask 3.x |
| Database | MySQL (via `mysql-connector-python`) |
| Auth | Session + OTP (bcrypt hashed) |
| Email | Flask-Mail (SMTP) / SendGrid HTTP API |
| Scheduler | APScheduler (background jobs) |
| Server | Waitress (production), Flask dev server (local) |
| Frontend | Jinja2 templates, HTML/CSS/JS |
| Container | Docker |
| Deployment | Render (via `render.yaml`) |

---

## 📁 Project Structure

```
MeetingRoomBookingSys/
├── backend/
│   ├── app.py               # Main Flask application (routes, auth, email)
│   └── functions.py         # Utility helpers
├── dataBase/
│   └── db_init.py           # DB connection, ORM-like helpers, queries
├── frontend/
│   ├── templates/           # Jinja2 HTML templates
│   │   ├── home.html
│   │   ├── login.html
│   │   ├── signup.html
│   │   ├── admin_dashboard.html
│   │   ├── admin_config.html
│   │   ├── admin_analytics.html
│   │   ├── admin_logs.html
│   │   ├── approver_dashboard.html
│   │   ├── requester_dashboard.html
│   │   ├── requester_booking.html
│   │   ├── halls.html
│   │   ├── gallery.html
│   │   ├── settings.html
│   │   └── ...
│   └── static/              # CSS, JS, images, uploads
├── database.sql             # Full DB schema + seed data
├── requirements.txt
├── Dockerfile
├── render.yaml              # Render cloud deployment config
├── .env.example             # Environment variable template
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.11+
- MySQL 8.0+
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/Slganeshkarthik/MeetingRoomBookingSys.git
cd MeetingRoomBookingSys
```

### 2. Set Up a Virtual Environment
```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure the Database
```bash
# Log into MySQL and run the schema
mysql -u root -p < database.sql
```

### 5. Configure Environment Variables
```bash
cp .env.example .env
```

Open `.env` and fill in your values:

```env
# Database
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=user_database

# Flask
SECRET_KEY=change_this_to_a_random_secret
APP_BASE_URL=http://localhost:5000

# SMTP (Gmail example)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USE_SSL=false
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_gmail_app_password
MAIL_DEFAULT_SENDER=your_email@gmail.com

# Admin Credentials
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
ADMIN_OTP_EMAIL=your_admin_email@gmail.com
```

> **💡 Gmail Tip:** Use an [App Password](https://myaccount.google.com/apppasswords) instead of your regular Gmail password when 2FA is enabled.

### 6. Run the Application
```bash
python backend/app.py
```

Visit [http://localhost:5000](http://localhost:5000) in your browser.

---

## 🐳 Docker

### Build and Run Locally
```bash
docker build -t meeting-room-booking .
docker run -p 5000:5000 --env-file .env meeting-room-booking
```

---

## ☁️ Deploy to Render

This project includes a `render.yaml` for one-click deployment on [Render](https://render.com).

1. Push this repository to GitHub.
2. Go to [Render Dashboard](https://dashboard.render.com) → **New** → **Blueprint**.
3. Connect your GitHub repo.
4. Set the required environment variables in Render's dashboard (see `.env.example`).
5. Deploy!

> **📧 Email on Render:** Render blocks outbound SMTP. Set `SENDGRID_API_KEY` in environment variables to use the SendGrid HTTP API instead of SMTP.

---

## 👤 Default Admin Login

| Field | Value |
|-------|-------|
| Username | `admin` (or as set in `.env`) |
| Password | `admin123` (or as set in `.env`) |
| OTP | Sent to `ADMIN_OTP_EMAIL` |

> **⚠️ Change default credentials immediately after first login.**

---

## 🔄 Approval Workflow

```
Requester submits booking
        ↓
  [Approver Level 1]  e.g., HOD
        ↓ approved
  [Approver Level 2]  e.g., Principal
        ↓ approved
  [Approver Level 3]  e.g., Secretary (optional)
        ↓ approved
    Booking Confirmed ✅
```

- The approval chain is **fully configurable** from the Admin Config panel.
- Each approver receives an **email with one-click approve/reject** links.
- Approvers can also **suggest an alternative time slot**.

---

## 📊 Analytics

- **Admin Analytics** — system-wide booking trends, approval rates, peak usage times
- **Approver Analytics** — personal approval history and performance metrics
- **Admin Logs** — security events, login attempts, system alerts

---

## 🛡️ Security Notes

- Never commit your `.env` file — it's already in `.gitignore`.
- Rotate `SECRET_KEY` before any production deployment.
- OTP codes expire in **5 minutes** and are hashed (bcrypt) in the database.
- Repeated login failures trigger security alerts to the admin email.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'Add my feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

---

*Built as part of a 4th semester mini project.*
