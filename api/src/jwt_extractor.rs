use jsonwebtoken::TokenData;
use tower_cookies::Cookies;

use crate::{
    types::{AppSettings, Claims, ValidateQueryParams},
    COOKIE_KEY,
};

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Redirect, Response},
};

pub struct ExtractJwt(pub Claims);

#[async_trait]
impl<S> FromRequestParts<S> for ExtractJwt
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let cookies = Cookies::from_request_parts(parts, state)
            .await
            .map_err(|_| (StatusCode::BAD_REQUEST, "Could not parse cookies").into_response());

        let cookie = if let Ok(c) = &cookies {
            c.get(COOKIE_KEY)
                .ok_or((StatusCode::BAD_REQUEST, "Missing authorization cookie").into_response())
        } else {
            Err((StatusCode::BAD_REQUEST, "Missing authorization cookie").into_response())
        };

        let app_settings = parts.extensions.get::<AppSettings>().ok_or(
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "AppSettings not injected",
            )
                .into_response(),
        )?;

        let jwt = cookie.and_then(|cookie| {
            jwt_decode(app_settings.jwt_secret.as_bytes(), cookie.value())
                .map_err(|_| (StatusCode::UNAUTHORIZED, "Unauthorized").into_response())
        });

        let query = serde_urlencoded::from_str::<ValidateQueryParams>(
            parts.uri.query().unwrap_or_default(),
        )
        .map_err(|_| (StatusCode::BAD_REQUEST, "Query not injected").into_response());

        if let Ok(token_data) = jwt {
            Ok(ExtractJwt(token_data.claims))
        } else if let Ok(true) = query.map(|q| q.disable_redirect.unwrap_or(false)) {
            Err(StatusCode::UNAUTHORIZED.into_response())
        } else {
            let url = parts
                .headers
                .get("x-forwarded-host")
                .zip(parts.headers.get("x-forwarded-port"))
                .map(|(host, port)| {
                    format!(
                        "{}?redirect={}://{}",
                        app_settings.domain,
                        if port.to_str().unwrap() == "443" {
                            "https"
                        } else {
                            "http"
                        },
                        host.to_str().unwrap()
                    )
                })
                .ok_or(StatusCode::UNAUTHORIZED.into_response())?;

            Err(Redirect::temporary(&url).into_response())
        }
    }
}

fn jwt_decode(
    secret: &[u8],
    jwt: &str,
) -> Result<TokenData<Claims>, jsonwebtoken::errors::Error> {
    jsonwebtoken::decode::<Claims>(
        jwt,
        &jsonwebtoken::DecodingKey::from_secret(secret),
        &jsonwebtoken::Validation::default(),
    )
}
