use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use axum::{Router, Extension, routing::{get, post}, Json, http::{StatusCode, Method, HeaderValue}, response::IntoResponse};
use rand_core::OsRng;
use sqlx::{Sqlite, Pool};
use tower_cookies::CookieManagerLayer;
use tower_http::cors::CorsLayer;

use crate::{types::AppSettings, requests::{CreateUserRequest, ListUsersResponse}, jwt_extractor::ExtractJwt};

async fn user_register(
    Extension(db): Extension<Pool<Sqlite>>,
    Json(body): Json<CreateUserRequest>,
) -> Result<StatusCode, StatusCode> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .to_string();

    let result = sqlx::query("INSERT INTO USERS (username, password) VALUES (?, ?)")
        .bind(body.username)
        .bind(password_hash)
        .execute(&db)
        .await;

    if let Err(e) = result {
        log::error!("{}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn list_users(
    ExtractJwt(_jwt): ExtractJwt,
    Extension(db): Extension<Pool<Sqlite>>,
) -> Result<impl IntoResponse, StatusCode> {
    let users: Vec<(String,)> = sqlx::query_as("SELECT username FROM USERS")
        .fetch_all(&db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ListUsersResponse {
        users: users.into_iter().map(|(u,)| u).collect()
    }))
}

pub async fn admin_server(
    app_settings: AppSettings,
    db: Pool<Sqlite>,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("0.0.0.0:{}", &app_settings.admin_port.unwrap_or(8888));
    let app = Router::new()
        .route("/", get(|| async { "hello" }))
        .route("/api/admin/users", get(list_users))
        .route("/api/admin/users", post(user_register))
        .layer(Extension(db))
        .layer(Extension(app_settings))
        .layer(CookieManagerLayer::new())
        .layer(CorsLayer::new()
               .allow_credentials(true)
               .allow_methods([Method::GET, Method::POST])
               .allow_origin("http://some.domain:8000".parse::<HeaderValue>().unwrap()));

    log::info!("Starting web server on: {}", addr);
    axum::Server::bind(&addr.parse()?)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

