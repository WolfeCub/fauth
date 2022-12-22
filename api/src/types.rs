use serde::{Serialize, Deserialize};
use ts_rs::TS;

#[derive(TS, Deserialize)]
#[ts(export)]
pub (crate) struct CreateUserRequest {
    pub username: String,
    pub password: String,
}

#[derive(TS, Deserialize)]
#[ts(export)]
pub (crate) struct CreateTotpRequest {
    pub username: String,
}

#[derive(TS, Serialize)]
#[ts(export)]
pub (crate) struct CreateTotpResponse {
    pub secret: String,
}

#[derive(TS, Serialize)]
#[ts(export)]
pub (crate) struct LoginResponse {
    pub jwt: String,
}
