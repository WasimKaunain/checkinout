# 🚪 CheckInOut - Hostel & Guesthouse Check-In/Out Management System

## 📘 Project Overview

**CheckInOut** is a comprehensive, full-stack database-driven system designed to manage the check-in/check-out process for **Students**, **Staff**, and **Visitors** in a university's **hostels**, **guesthouses**, and **mess facilities**. It provides secure authentication, room tracking, mess attendance, guestroom request workflows, and QR-based access, all connected via a robust **Flask + MySQL backend** and managed with **SQLAlchemy ORM**, **triggers**, and **multi-table synchronization**.

---

## ⚙️ Technologies Used

- **Frontend**: HTML/CSS (mobile app & web planned using React/Flutter)
- **Backend**: Python (Flask)
- **Database**: MySQL (with triggers, foreign keys, constraints)
- **ORM**: SQLAlchemy
- **Session Management**: Flask session with timed expiry
- **QR Code Integration**: Python + Mobile Camera App (API-integrated)
- **API**: RESTful routes for login, room status, check-ins, etc.

---

## 🧱 System Modules

### 🔐 Authentication
- Registration/Login for Students, Staff, Visitors
- Sessions stored in `Login` table (with expiry & roles)
- Passwords stored securely with hashing

### 🏢 Hostel Management
- Hostel room allotment
- Vacancy status auto-updated using **MySQL Triggers**
- Check-in/check-out logs for students

### 🛏 Guesthouse Management
- Allotment requests via form (Students/Staff)
- Admin approval system
- Auto-vacancy management on check-in/check-out

### 🍽 Mess Management
- Student mess allotment
- Mess attendance tracking via QR
- Reporting of usage patterns

### 📱 Mobile + QR Code Support
- QR generated on student registration
- QR types: hostel check-in, mess entry, guest check-in
- Mobile camera scans QR → sends API call to insert check-in record

---

## 🗃️ Database Structure

### 🔧 Key Tables

| Table | Description |
|-------|-------------|
| `Students` | Profile data for students |
| `Visitors` | Visitor profile and contact info |
| `Staff` | Staff member profiles |
| `Users` | Common user authentication table |
| `Hostels` | Hostel metadata |
| `HostelRoom` | Individual hostel room details with capacity, vacancy |
| `Guesthouse` | Metadata for guesthouses |
| `GuestRoom` | Guesthouse rooms |
| `HostelCheckInOut` | Student check-in/out log |
| `GuestCheckInOut` | Visitor check-in/out log |
| `Mess` | Mess metadata |
| `MessCheckInOut` | Logs mess attendance via QR |
| `GuestroomRequest` | Form data and status for guestroom requests |
| `Login` | Auth table for session + hashed passwords |
| `Members`, `MemberGroupMapping` | Evaluation DB syncing for role-group tracking |
| `images` | (Optional) Profile image management |

### 🔁 Triggers

- When a hostel room is **allocated**, a trigger **updates vacancy to false**
- When a user **checks out**, vacancy is **set to true**
- Similarly for **guesthouse rooms**

---

## 🧭 File & Directory Structure
<pre> ``` checkinout/ ├── app/ │ ├── __init__.py │ ├── models.py │ ├── routes/ │ │ ├── auth.py │ │ ├── student.py │ │ ├── staff.py │ │ ├── visitor.py │ │ └── admin.py │ ├── templates/ │ │ ├── student/ │ │ │ ├── profile.html │ │ │ └── guestroom_status.html │ │ ├── login.html │ │ └── dashboard.html │ ├── static/ │ │ ├── css/ │ │ └── images/ ├── database/ │ ├── init.sql │ └── triggers.sql ├── qr/ │ └── generate_qr.py ├── mobile_api/ │ └── api.py ├── run.py ├── config.py └── README.md ``` </pre>
---

## 🧪 Setup & Installation

### ✅ Requirements
- Python 3.9+
- MySQL 8.0+
- Pipenv or virtualenv recommended

### 🔧 Steps

```bash
# Clone repository
git clone https://github.com/WasimKaunain/checkinout.git
cd checkinout

# Set up environment
pip install -r requirements.txt

# Initialize MySQL DB
mysql -u root -p < database/init.sql
mysql -u root -p < database/triggers.sql

# Run the Flask app
python run.py
