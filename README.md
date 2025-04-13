# CheckInOut - Hostel Check-In/Out Management System

## 📌 Project Description
CheckInOut is a database-driven management system designed to streamline the check-in and check-out process for university hostel accommodations. The system allows students and visitors to register, log in, and check room availability in hostels and guesthouses. It also manages room allocations, mess assignments, and check-in records efficiently.

## 🚀 Features
- **User Authentication:** Secure login/signup for students and visitors.
- **Room Management:** Check available hostel/guesthouse rooms, allot rooms, and update vacancy status automatically.
- **Check-In/Check-Out Tracking:** Maintain records for hostel and guestroom check-ins/check-outs.
- **Mess Management:** Track student mess allocations and check-ins.
- **Triggers & Constraints:** Auto-update room status when allocated or vacated.

## 🛠️ Technologies Used
- **Database:** MySQL
- **Backend:** Python (Flask/Django) *(Planned for future)*
- **Frontend:** React/Flutter *(Planned for future)*

## 📂 Database Schema Overview
### **Tables**
- `Users` - Stores login credentials for students and visitors.
- `Students` - Student profile details and allotted hostel room.
- `Visitors` - Visitor details and guestroom allotment.
- `Staff` - University staff records.
- `HostelRooms` - Hostel room details, vacancy status.
- `GuestRooms` - Guesthouse room details, vacancy status.
- `Hostels` - Information on university hostels.
- `Guesthouses` - Information on guesthouses.
- `CheckInOut` - Tracks check-in/check-out of students and visitors.
- `Mess` - Details of mess facilities.
- `MessCheckIn` - Student mess attendance records.

## 🏗️ Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/WasimKaunain/checkinout.git
   ```
2. Set up the database:
   - Ensure MySQL is installed and running.
   - Run the provided SQL script to create the necessary tables.
   ```sh
   mysql -u root -p < checkinout_schema.sql
   ```

## 📌 Usage
1. **Run the application** *(Future implementation)*:
   ```sh
   python run.py  # Starts the backend server
   ```
2. **Login/Register** as a Student or Visitor.
3. **Check available rooms** and request an allotment.
4. **Check-in/Check-out** and track visit history.

## 📖 API Endpoints *(Planned for future implementation)*
| Method | Endpoint | Description |
|--------|----------------|----------------|
| GET | `/rooms/vacant` | Fetch all vacant rooms |
| POST | `/checkin` | Check-in a student/visitor |
| POST | `/checkout` | Check-out a student/visitor |

## 🤝 Contribution
Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a new branch.
3. Commit changes and create a pull request.

## 📜 License
This project is licensed under the MIT License.

## 📩 Contact
For queries, contact wasimkonain@gmail.com

