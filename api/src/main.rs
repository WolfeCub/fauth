mod requests;
mod types;
mod admin;
mod jwt_extractor;

use std::{env, fs, io, time::SystemTime};

use data_encoding::BASE32;
use requests::{CreateTotpRequest, CreateTotpResponse, CreateUserRequest};
use tower_http::services::{ServeDir, ServeFile};
use types::{AppSettings, Claims, User};

use argon2::{
    Argon2, PasswordHash, PasswordVerifier,
};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, get_service, post},
    Extension, Json, Router,
};
use rand::Rng;
use simplelog::{ColorChoice, CombinedLogger, Config, TermLogger, TerminalMode};
use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};
use jwt_extractor::ExtractJwt;

use crate::admin::admin_server;

const COOKIE_KEY: &'static str = "fauth_token";

async fn get_user(db: &Pool<Sqlite>, username: &str) -> Result<User, sqlx::Error> {
    sqlx::query_as("SELECT password, admin FROM USERS WHERE username = ?")
        .bind(username)
        .fetch_one(db)
        .await
}

async fn register_user_totp(
    Extension(db): Extension<Pool<Sqlite>>,
    Json(body): Json<CreateTotpRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    get_user(&db, &body.username)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let secret = rand::thread_rng().gen::<[u8; 32]>();
    let encoded_secret = BASE32.encode(&secret);

    let result = sqlx::query("INSERT INTO USERS (username, totp_secret) VALUES (?, ?)")
        .bind(&body.username)
        .bind(&encoded_secret)
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

async fn user_login(
    cookies: Cookies,
    Extension(app_settings): Extension<AppSettings>,
    Extension(db): Extension<Pool<Sqlite>>,
    Json(body): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let user = get_user(&db, &body.username)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let parsed_hash = PasswordHash::new(&user.password).unwrap();

    if Argon2::default()
        .verify_password(body.password.as_bytes(), &parsed_hash)
        .is_err()
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let expiration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let claim = Claims {
        exp: expiration as usize + 86400,
        sub: body.username,
        admin: user.admin,
    };

    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claim,
        &jsonwebtoken::EncodingKey::from_secret(app_settings.jwt_secret.as_bytes()),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    cookies.add(
        Cookie::build(COOKIE_KEY, token)
            .domain(app_settings.cookie_domain)
            .path("/")
            .finish(),
    );

    Ok(StatusCode::OK)
}

async fn validate_token(
    ExtractJwt(_): ExtractJwt,
) -> Response {
    ().into_response()
}

async fn app_server(
    app_settings: AppSettings,
    db: Pool<Sqlite>,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("0.0.0.0:{}", &app_settings.port.unwrap_or(8000));

    async fn handle_error(e: io::Error) -> impl IntoResponse {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unexpected error: {}", e),
        )
    }
    let spa = get_service(
        ServeDir::new("../ui/dist").not_found_service(ServeFile::new("../ui/dist/index.html")),
    )
    .handle_error(handle_error);

    let app = Router::new()
        .route("/api/user/totp", post(register_user_totp))
        .route("/api/user/login", post(user_login))
        .route("/api/verify", get(validate_token))
        .layer(Extension(db))
        .layer(Extension(app_settings))
        .layer(CookieManagerLayer::new())
        .fallback_service(spa);

    log::info!("Starting web server on: {}", addr);
    axum::Server::bind(&addr.parse()?)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app_settings = serde_yaml::from_str::<AppSettings>(
        &fs::read_to_string(env::var("FAUTH_CONFIG").unwrap_or("/etc/fauth.yaml".to_owned()))
            .expect("Unable to open config file"),
    )
    .expect("Error parsing config file");

    CombinedLogger::init(vec![TermLogger::new(
        app_settings.level_filter,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )])?;

    let db = SqlitePoolOptions::new()
        .connect("sqlite:db.sqlite?mode=rwc")
        .await?;

    log::info!("Running migrations...");
    sqlx::migrate!().run(&db).await?;
    log::info!("Migrations complete.");

    let app = app_server(app_settings.clone(), db.clone());
    let admin = admin_server(app_settings, db);

    tokio::try_join!(app, admin).unwrap();

    Ok(())
}
