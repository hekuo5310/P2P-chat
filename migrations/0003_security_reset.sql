-- Security reset: invalidates all legacy accounts, groups, ciphertexts and keys.
PRAGMA foreign_keys = OFF;
DROP TABLE IF EXISTS group_members;
DROP TABLE IF EXISTS chat_groups;
DROP TABLE IF EXISTS users;
PRAGMA foreign_keys = ON;

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  encryption_key TEXT NOT NULL,
  signing_key TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE chat_groups (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  owner_id TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL
);
CREATE TABLE group_members (
  group_id TEXT NOT NULL REFERENCES chat_groups(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  joined_at INTEGER NOT NULL,
  PRIMARY KEY (group_id, user_id)
);
CREATE INDEX group_members_user ON group_members(user_id);