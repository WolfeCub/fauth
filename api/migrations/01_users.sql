CREATE TABLE USERS(
    username    STRING  PRIMARY KEY,
    password    STRING  NOT NULL,
    admin       BOOLEAN NOT NULL DEFAULT FALSE,
    totp_secret STRING      NULL
);
