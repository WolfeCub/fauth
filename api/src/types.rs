use log::LevelFilter;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[derive(sqlx::FromRow)]
pub struct User {
    pub password: String,
    pub totp_secret: String,
}


#[derive(Debug, Deserialize)]
pub struct ValidateQueryParams {
    pub disable_redirect: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub level_filter: LevelFilter,
    pub cookie_domain: String,
    pub jwt_secret: String,
    pub domain: String,
    pub port: Option<u32>,
    pub admin_port: Option<u32>,
}

