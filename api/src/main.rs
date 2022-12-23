mod types;
mod requests;

use std::{env, fs, time::SystemTime};

use axum_extra::routing::SpaRouter;
use data_encoding::BASE32;
use requests::{CreateTotpRequest, CreateTotpResponse, CreateUserRequest};
use types::{AppSettings, User, Claims, ValidateQueryParams};

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use axum::{
    extract,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use rand::Rng;
use simplelog::{ColorChoice, CombinedLogger, Config, TermLogger, TerminalMode};
use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};

const COOKIE_KEY: &'static str = "fauth_token";

async fn get_user(db: &Pool<Sqlite>, username: &str) -> Result<User, sqlx::Error> {
    sqlx::query_as("SELECT password, totp_secret FROM USERS WHERE username = ?")
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

async fn user_login(
    cookies: Cookies,
    Extension(app_settings): Extension<AppSettings>,
    Extension(db): Extension<Pool<Sqlite>>,
    Json(body): Json<CreateUserRequest>,
) -> Result<StatusCode, StatusCode> {
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
        sub: body.username,
        exp: expiration as usize + 86400,
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
    headers: HeaderMap,
    cookies: Cookies,
    query: extract::Query<ValidateQueryParams>,
    Extension(app_settings): Extension<AppSettings>,
) -> Response {
    let jwt = cookies.get(COOKIE_KEY).and_then(|token| {
        jsonwebtoken::decode::<Claims>(
            &token.value(),
            &jsonwebtoken::DecodingKey::from_secret(app_settings.jwt_secret.as_bytes()),
            &jsonwebtoken::Validation::default(),
        )
        .ok()
    });

    if let Some(_token_data) = jwt {
        ().into_response()
    } else if let Some(true) = query.disable_redirect {
        StatusCode::UNAUTHORIZED.into_response()
    } else {
        let (host, port) = headers
            .get("x-forwarded-host")
            .zip(headers.get("x-forwarded-port"))
            .expect("Missing headers");
        let url = format!(
            "{}?redirect={}://{}",
            app_settings.domain,
            if port.to_str().unwrap() == "443" {
                "https"
            } else {
                "http"
            },
            host.to_str().unwrap()
        );
        Redirect::temporary(&url).into_response()
    }
}

async fn app_server(app_settings: AppSettings, db: Pool<Sqlite>) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("0.0.0.0:{}", &app_settings.port.unwrap_or(8000));
    let app = Router::new()
        .merge(SpaRouter::new("/", "../ui/dist"))
        .route("/api/user/register", post(user_register))
        .route("/api/user/totp", post(register_user_totp))
        .route("/api/user/login", post(user_login))
        .route("/api/verify", get(validate_token))
        .layer(Extension(db))
        .layer(Extension(app_settings))
        .layer(CookieManagerLayer::new());

    log::info!("Starting web server on: {}", addr);
    axum::Server::bind(&addr.parse()?)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

async fn admin_server(app_settings: AppSettings, db: Pool<Sqlite>) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("0.0.0.0:{}", &app_settings.admin_port.unwrap_or(8888));
    let app = Router::new()
        .route("/", get(|| async { "hello" }))
        .layer(Extension(db))
        .layer(Extension(app_settings))
        .layer(CookieManagerLayer::new());

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
