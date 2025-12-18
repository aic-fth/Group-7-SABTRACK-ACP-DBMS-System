# Users table
CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT(50) UNIQUE NOT NULL,
        email TEXT(100) UNIQUE NOT NULL,
        password TEXT(255) NOT NULL,
        full_name TEXT(100) NOT NULL,
        age INTEGER,
        address TEXT(150) NOT NULL,
        resident_id TEXT(50),
        phone TEXT(20),
        role TEXT(20) NOT NULL DEFAULT 'resident',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)

# Waste schedules table
CREATE TABLE IF NOT EXISTS schedules (
        schedule_id INTEGER PRIMARY KEY AUTOINCREMENT,
        day TEXT(20) NOT NULL,
        area TEXT(100) NOT NULL,
        waste_type TEXT(50) NOT NULL,
        time_start TEXT(10) NOT NULL,
        time_end TEXT(10) NOT NULL
    )

# Garbage reports table
CREATE TABLE IF NOT EXISTS reports (
        report_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        issue_type TEXT(100) NOT NULL,
        location TEXT(150) NOT NULL,
        description TEXT(500) NOT NULL,
        photo_path TEXT(255),
        status TEXT(20) NOT NULL DEFAULT 'pending',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(user_id)
    )

# Announcements table
CREATE TABLE IF NOT EXISTS announcements (
        announcement_id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT(150) NOT NULL,
        content TEXT(1000) NOT NULL,
        created_by INTEGER NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users(user_id)
    )

# Reminders table
CREATE TABLE IF NOT EXISTS reminders (
        reminder_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        schedule_id INTEGER NOT NULL,
        enabled BOOLEAN NOT NULL DEFAULT 1,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(user_id),
        FOREIGN KEY (schedule_id) REFERENCES schedules(schedule_id)
    )

# Notifications table
CREATE TABLE IF NOT EXISTS notifications (
        notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        type TEXT(50) NOT NULL,
        title TEXT(150) NOT NULL,
        content TEXT(500) NOT NULL,
        related_id INTEGER,
        is_read BOOLEAN NOT NULL DEFAULT 0,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(user_id)
    )

# Activities table
CREATE TABLE IF NOT EXISTS activities (
        activity_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        activity_type TEXT(50) NOT NULL,
        description TEXT(200) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(user_id)
    )
