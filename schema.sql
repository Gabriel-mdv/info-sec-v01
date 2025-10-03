-- Information Security Fall 2025 Lab - Database Schema
-- Central place for schema so you can add future tables here.

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS files;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    andrew_id TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);


CREATE TABLE files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    stored_name TEXT NOT NULL, -- the actual saved filename on disk
    size INTEGER NOT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);


CREATE TABLE otp_chain (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    otp TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id)
)