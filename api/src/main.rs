mod types;

use std::time::SystemTime;

use axum_extra::routing::SpaRouter;
use data_encoding::BASE32;
use serde::{Serialize, Deserialize};
use types::{CreateTotpResponse, CreateUserRequest, CreateTotpRequest};

use axum::{
    routing::{get, post},
    Router, response::{IntoResponse, Redirect, Response}, http::{StatusCode, HeaderMap}, Json, Extension, extract,
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
use tower_cookies::{CookieManagerLayer, Cookies, Cookie};

const COOKIE_KEY: &'static str = "fauth_token";
const JWT_SECRET: &'static [u8] = b"A5btxFk53jV7nHnSoEW+iSZg8o4Ypmmj1hjnbZhb1IAbPLG8dAbW3Bvwp3k736cc";

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
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
    cookies: Cookies,
    Extension(db): Extension<Pool<Sqlite>>,
    Json(body): Json<CreateUserRequest>,
) -> Result<StatusCode, StatusCode> {
    let user = get_user(&db, &body.username).await.map_err(|_| StatusCode::NOT_FOUND)?;

    let parsed_hash = PasswordHash::new(&user.password).unwrap();

    if Argon2::default().verify_password(body.password.as_bytes(), &parsed_hash).is_err() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let expiration = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    let claim = Claims {
        sub: body.username,
        exp: expiration as usize + 86400,
    };

    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(), 
        &claim, 
        &jsonwebtoken::EncodingKey::from_secret(JWT_SECRET)
    ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    cookies.add(Cookie::build(COOKIE_KEY, token)
        .domain("foo.blah")
        .path("/")
        .finish());

    Ok(StatusCode::OK)
}

#[derive(Debug, Deserialize)]
struct ValidateQueryParams {
    disable_redirect: Option<bool>,
}

async fn validate_token(
    headers: HeaderMap,
    cookies: Cookies,
    query: extract::Query<ValidateQueryParams>,
) -> Response {
    let jwt = cookies.get(COOKIE_KEY).and_then(|token| {
        jsonwebtoken::decode::<Claims>(
            &token.value(), 
            &jsonwebtoken::DecodingKey::from_secret(JWT_SECRET), 
            &jsonwebtoken::Validation::default())
            .ok()
    });

    if let Some(_token_data) = jwt {
        ().into_response()
    } else if let Some(true) = query.disable_redirect {
        StatusCode::UNAUTHORIZED.into_response()
    } else {
        let (host, port) = headers.get("x-forwarded-host").zip(headers.get("x-forwarded-port")).expect("Missing headers");
        let url = format!("http://fauth.foo.blah?redirect={}://{}", if port.to_str().unwrap() == "443" { "https" } else { "http" }, host.to_str().unwrap());
        Redirect::temporary(&url).into_response()
    }
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

    let spa = SpaRouter::new("/", "../ui/dist");
    let app = Router::new()
        .merge(spa)
        .route("/api/user/register", post(user_register))
        .route("/api/user/totp", post(register_user_totp))
        .route("/api/user/login", post(user_login))
        .route("/api/verify", get(validate_token))
        .layer(Extension(db))
        .layer(CookieManagerLayer::new());

    let addr = "0.0.0.0:8000";
    log::info!("Starting web server on: {}", addr);
    axum::Server::bind(&addr.parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();

    return Ok(())
}
