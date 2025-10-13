-- Information Security Fall 2025 Lab - Database Schema
-- Central place for schema so you can add future tables here.

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS files;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    andrew_id TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'basic' CHECK (role IN ('basic', 'user_admin', 'data_admin'))
);
CREATE INDEX idx_andrew_id ON users(andrew_id);

CREATE TABLE files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    stored_name TEXT NOT NULL, -- the actual saved filename on disk
    size INTEGER NOT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX idx_user_id ON files(user_id);

CREATE TABLE otp_chain (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    otp TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    actor_andrew_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    outcome TEXT NOT NULL CHECK (outcome IN ('allowed', 'denied')),
    FOREIGN KEY (actor_andrew_id) REFERENCES users(andrew_id)
);



---- seed data for testing -----

-- INSERT INTO users (name, andrew_id, password, role) VALUES
-- ('Alice Admin', 'alice', generate_password_hash('adminpass'), 'data_admin'), -- password: adminpass
-- ('Bob Basic', 'bob', generate_password_hash('basicpass'), 'basic'), -- password: basicpass
-- ('Charlie UserAdmin', 'charlie', generate_password_hash('useradminpass'), 'user_admin'); -- password: useradminpass

-- -- Note: The passwords above are hashed versions of 'adminpass', 'basicpass', and 'useradminpass' respectively.

-- INSERT INTO files (user_id, filename, stored_name, size) VALUES
-- (1, 'report.pdf', 'file_1_report.pdf', 204800),
-- (2, 'photo.jpg', 'file_2_photo.jpg', 512000),
-- (3, 'data.csv', 'file_3_data.csv', 102400);

-- INSERT INTO otp_chain (user_id, timestamp, otp) VALUES
-- (1, 1700000000, 'otp1_for_alice'),
-- (1, 1700003600, 'otp2_for_alice'),
-- (2, 1700000000, 'otp1_for_bob'),
-- (3, 1700000000, 'otp1_for_charlie');

-- INSERT INTO audit_logs (actor_andrew_id, action, target, outcome) VALUES
-- ('alice', 'create_user', 'bob', 'allowed'),
-- ('bob', 'upload_file', 'photo.jpg', 'allowed'),
-- ('charlie', 'delete_user', 'bob', 'denied');

-- -- End of schema and seed data
