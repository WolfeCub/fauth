mod types;

use std::time::{SystemTime, Duration};

use axum_auth::AuthBearer;
use data_encoding::BASE32;
use serde::{Serialize, Deserialize};
use types::{CreateTotpResponse, CreateUserRequest, CreateTotpRequest, LoginResponse};

use axum::{
    routing::{get, post},
    Router, response::IntoResponse, http::StatusCode, Json, Extension,
};
use log::LevelFilter;
use rand::Rng;
use simplelog::{CombinedLogger, TermLogger, Config, TerminalMode, ColorChoice};
use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHasher, SaltString
    },
    Argon2, PasswordHash, PasswordVerifier
};

const JWT_SECRET: &'static [u8] = b"A5btxFk53jV7nHnSoEW+iSZg8o4Ypmmj1hjnbZhb1IAbPLG8dAbW3Bvwp3k736cc";

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: u32,
    exp: usize,
}

#[derive(sqlx::FromRow)]
struct User {
    password: String,
    totp_secret: String,
}

async fn get_user(
    db: &Pool<Sqlite>,
    username: &str
) -> Result<User, sqlx::Error> {
    sqlx::query_as("SELECT password, totp_secret FROM USERS WHERE username = ?")
        .bind(username)
        .fetch_one(db)
        .await
}

async fn register_user_totp(
    Extension(db): Extension<Pool<Sqlite>>,
    Json(body): Json<CreateTotpRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    get_user(&db, &body.username).await.map_err(|_| StatusCode::NOT_FOUND)?;

    let secret = rand::thread_rng().gen::<[u8; 32]>();
    let encoded_secret = BASE32.encode(&secret);

    let result = sqlx::query("UPDATE USERS SET totp_secret = ? WHERE username = ?")
        .bind(&encoded_secret)
        .bind(&body.username)
        .execute(&db)
        .await;

    if let Err(e) = result {
        log::error!("{}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    // let seconds = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    // let result = totp_custom::<Sha1>(DEFAULT_STEP, 6, &secret, seconds);
    // dbg!(result);

    Ok(Json(CreateTotpResponse {
        secret: encoded_secret,
    }))
}

async fn user_register(
    Extension(db): Extension<Pool<Sqlite>>,
    Json(body): Json<CreateUserRequest>,
) -> Result<StatusCode, StatusCode> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(body.password.as_bytes(), &salt).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.to_string();

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

async fn user_login(
    Extension(db): Extension<Pool<Sqlite>>,
    Json(body): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let user = get_user(&db, &body.username).await.map_err(|_| StatusCode::NOT_FOUND)?;

    let parsed_hash = PasswordHash::new(&user.password).unwrap();

    if Argon2::default().verify_password(body.password.as_bytes(), &parsed_hash).is_err() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let expiration = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    let claim = Claims {
        sub: 1,
        exp: expiration as usize + 86400,
    };

    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(), 
        &claim, 
        &jsonwebtoken::EncodingKey::from_secret(JWT_SECRET)
    ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(LoginResponse {
        jwt: token,
    }))
}

async fn validate_token(
    AuthBearer(token): AuthBearer,
) -> Result<(), StatusCode> {
    let jwt = jsonwebtoken::decode::<Claims>(
        &token, 
        &jsonwebtoken::DecodingKey::from_secret(JWT_SECRET), 
        &jsonwebtoken::Validation::default()
    ).map_err(|_| StatusCode::UNAUTHORIZED)?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    CombinedLogger::init(vec![
        TermLogger::new(LevelFilter::Info, Config::default(), TerminalMode::Mixed, ColorChoice::Auto),
    ])?;

    let db = SqlitePoolOptions::new()
        .connect("sqlite:db.sqlite?mode=rwc")
        .await?;

    log::info!("Running migrations...");
    sqlx::migrate!()
        .run(&db)
        .await?;
    log::info!("Migrations complete.");

    // build our application with a single route
    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/api/user/register", post(user_register))
        .route("/api/user/totp", post(register_user_totp))
        .route("/api/user/login", post(user_login))
        .route("/api/validate_token", get(validate_token))
        .layer(Extension(db));

    let addr = "0.0.0.0:8000";
    log::info!("Starting web server on: {}", addr);
    axum::Server::bind(&addr.parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();

    return Ok(())
}
