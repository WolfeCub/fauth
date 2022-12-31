PRAGMA foreign_keys = ON;

CREATE TABLE USERS(
    username    STRING  PRIMARY KEY,
    password    STRING  NOT NULL,
    admin       BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE TOTP(
    username    STRING  NOT NULL,
    totp_secret STRING      NULL,
    FOREIGN KEY (username) REFERENCES USERS (username)
);
