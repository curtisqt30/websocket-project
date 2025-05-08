-- 1) Create the database and switch to it
CREATE DATABASE IF NOT EXISTS securechat CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE securechat;

-- 2) Users table
CREATE TABLE IF NOT EXISTS users (
  id            INT           AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(50)   NOT NULL UNIQUE,
  password_hash VARCHAR(100)  NOT NULL,
  created_at    TIMESTAMP     DEFAULT CURRENT_TIMESTAMP
);

-- 3) Rooms table
CREATE TABLE IF NOT EXISTS rooms (
  id         INT         AUTO_INCREMENT PRIMARY KEY,
  room_code  CHAR(4)     NOT NULL UNIQUE,
  created_at TIMESTAMP   DEFAULT CURRENT_TIMESTAMP
);

-- 4) Messages table
CREATE TABLE IF NOT EXISTS messages (
  id         BIGINT      AUTO_INCREMENT PRIMARY KEY,
  room_id    INT         NOT NULL,
  user_id    INT         NOT NULL,
  text       TEXT        NOT NULL,
  timestamp  TIMESTAMP   DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (room_id)  REFERENCES rooms(id)  ON DELETE CASCADE,
  FOREIGN KEY (user_id)  REFERENCES users(id)  ON DELETE CASCADE
);
