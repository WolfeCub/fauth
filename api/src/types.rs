use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct CreateTotpRequest {
    pub username: String,
}

#[derive(Serialize, Deserialize)]
pub struct CreateTotpResponse {
    pub secret: String,
}
