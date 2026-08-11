-- ============================================================
-- Database schema for the experimental web application
-- Master's thesis: Analysis and Protection of Web Applications
--                    Against OWASP Top 10 Attacks
-- ============================================================
--
-- Tables are kept minimal and purpose-built - only the fields
-- needed for the three demonstration scenarios:
--   users     -> SQL Injection (login)
--   comments  -> Stored XSS (posting/rendering a comment)
--   users.email -> CSRF (profile data update)

DROP TABLE IF EXISTS comments;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    -- Password is stored as a hash (werkzeug.security), NOT plaintext,
    -- even in the "vulnerable" version - the goal is to demonstrate SQL
    -- Injection in the login query's WHERE clause itself, not bad
    -- password-storage practice.
    password_hash TEXT NOT NULL,
    email         TEXT NOT NULL,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE comments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    content     TEXT NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Seed users for demonstration and manual testing.
-- Password for both is "password123" (hashed by the seed script,
-- not here). INSERTs are done programmatically via seed.py, so the
-- correct hashing is used from the very start.
