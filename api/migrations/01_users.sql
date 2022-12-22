CREATE TABLE USERS(
    username    STRING PRIMARY KEY,
    password    STRING NOT NULL,
    totp_secret STRING     NULL
);
