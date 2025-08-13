CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    verification BOOLEAN NOT NULL DEFAULT FALSE, --verification w otp
    status BOOLEAN NOT NULl DEFAULT FALSE, --online, offline
    created_at TIMESTAMP DEFAULT NOW(),
    role VARCHAR(20) NOT NULL --Admin, Guest, Student, HR
);

CREATE TABLE otp (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    otp_code VARCHAR(255) NOT NULL,
    purpose VARCHAR(20) NOT NULL, -- 'Reset', 'Verify'
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL
);