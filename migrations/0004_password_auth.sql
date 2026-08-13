ALTER TABLE users ADD COLUMN password_salt TEXT;
ALTER TABLE users ADD COLUMN password_hash TEXT;
CREATE INDEX IF NOT EXISTS users_email_password ON users(email);