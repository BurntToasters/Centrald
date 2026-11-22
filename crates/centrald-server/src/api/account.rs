//! First-run setup, sign-in, the operator's own account, and other operators.

use axum::extract::{Path, State};
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::{Json, extract::Request};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::auth;
use crate::db::{self, now};
use crate::error::{ApiError, ApiResult};
use crate::session::{self, CurrentUser, Peer};
use crate::state::Shared;

pub const SETUP_CODE_KEY: &str = "setup_code";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserView {
    pub id: String,
    pub username: String,
    pub totp_enabled: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StateView {
    pub setup_required: bool,
    pub user: Option<UserView>,
    pub version: &'static str,
}

async fn user_count(state: &Shared) -> ApiResult<i64> {
    Ok(state
        .db
        .call(|c| Ok(c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?))
        .await?)
}

/// Unauthenticated: tells the app which screen to show.
pub async fn get_state(
    State(state): State<Shared>,
    request: Request,
) -> ApiResult<Json<StateView>> {
    let setup_required = user_count(&state).await? == 0;
    let (mut parts, _) = request.into_parts();
    let user = if setup_required {
        None
    } else {
        use axum::extract::FromRequestParts;
        CurrentUser::from_request_parts(&mut parts, &state)
            .await
            .ok()
            .map(|user| UserView {
                id: user.id,
                username: user.username,
                totp_enabled: user.totp_enabled,
            })
    };
    Ok(Json(StateView {
        setup_required,
        user,
        version: centrald_proto::VERSION,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetupRequest {
    setup_code: String,
    username: String,
    password: String,
}

/// Creates the first operator. Requires the setup code printed by the server.
pub async fn setup(
    State(state): State<Shared>,
    Peer(address): Peer,
    headers: HeaderMap,
    Json(body): Json<SetupRequest>,
) -> ApiResult<impl IntoResponse> {
    let key = format!("setup:{address}");
    state
        .login_limiter
        .check(&key)
        .map_err(ApiError::too_many)?;
    if user_count(&state).await? > 0 {
        return Err(ApiError::conflict(
            "This server is already set up. Sign in instead.",
        ));
    }
    let expected = state
        .db
        .call(|c| db::get_setting(c, SETUP_CODE_KEY))
        .await?
        .unwrap_or_default();
    if expected.is_empty() || !auth::setup_code_matches(&expected, &body.setup_code) {
        state.login_limiter.record_failure(&key);
        return Err(ApiError::forbidden(
            "That setup code is not right. Run `sudo centrald-server status` on the server to see it.",
        ));
    }
    let username = body.username.trim().to_owned();
    auth::validate_username(&username).map_err(ApiError::bad_request)?;
    auth::validate_password(&body.password, &username).map_err(ApiError::bad_request)?;
    let password = body.password;
    let hash = state
        .hashing(move || auth::hash_password(&password))
        .await??;

    let id = uuid::Uuid::new_v4().to_string();
    let user_id = id.clone();
    let audit_user = username.clone();
    let audit_address = address.clone();
    let created = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            // Re-check inside the transaction so two racing setups cannot
            // both win.
            let count: i64 = tx.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
            if count > 0 {
                return Ok(false);
            }
            tx.execute(
                "INSERT INTO users (id, username, password_hash, created_at) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![user_id, username, hash, now()],
            )?;
            db::delete_setting(&tx, SETUP_CODE_KEY)?;
            db::audit(&tx, &audit_user, "setup.completed", &audit_user, "", &audit_address)?;
            tx.commit()?;
            Ok(true)
        })
        .await?;
    if !created {
        return Err(ApiError::conflict(
            "This server is already set up. Sign in instead.",
        ));
    }
    state.login_limiter.record_success(&key);
    let cookie = session::start_session(&state, id, &headers, address).await?;
    Ok(([(SET_COOKIE, cookie)], Json(json!({ "ok": true }))))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoginRequest {
    username: String,
    password: String,
    #[serde(default)]
    totp_code: Option<String>,
}

/// Signs an operator in.
///
/// Both limiter keys count this attempt before any hashing, so parallel
/// guesses cannot all be verified. The rest runs on its own task: a client
/// that hangs up mid-hash still leaves its audit row and limiter count.
pub async fn login(
    State(state): State<Shared>,
    Peer(address): Peer,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> ApiResult<impl IntoResponse> {
    let username = body.username.trim().to_owned();
    if username.len() > auth::MAX_USERNAME_BYTES || body.password.len() > auth::MAX_PASSWORD_BYTES {
        return Err(ApiError::unauthorized("Wrong username or password."));
    }
    let address_key = format!("login:{address}");
    let user_key = format!("user:{}", username.to_ascii_lowercase());
    state
        .login_limiter
        .attempt(&address_key)
        .and_then(|()| state.login_limiter.attempt(&user_key))
        .map_err(ApiError::too_many)?;
    let attempt = LoginAttempt {
        username,
        password: body.password,
        totp_code: body.totp_code,
        address,
        address_key,
        user_key,
    };
    let cookie = tokio::spawn(finish_login(state, attempt, headers))
        .await
        .map_err(anyhow::Error::from)??;
    Ok(([(SET_COOKIE, cookie)], Json(json!({ "ok": true }))))
}

struct LoginAttempt {
    username: String,
    password: String,
    totp_code: Option<String>,
    address: String,
    address_key: String,
    user_key: String,
}

async fn login_audit(
    state: &Shared,
    actor: &str,
    action: &'static str,
    detail: &'static str,
    address: &str,
) -> ApiResult<()> {
    let (actor, address) = (actor.to_owned(), address.to_owned());
    state
        .db
        .call(move |c| db::audit(c, &actor, action, &actor, detail, &address))
        .await?;
    Ok(())
}

struct SecondFactor<'a> {
    user_id: &'a str,
    canonical: &'a str,
    secret: String,
    last_step: i64,
    address: &'a str,
}

/// Checks the two-factor code after a correct password and audits the
/// outcome either way.
async fn second_factor(
    state: &Shared,
    factor: SecondFactor<'_>,
    code: Option<String>,
) -> ApiResult<()> {
    let SecondFactor {
        user_id,
        canonical,
        secret,
        last_step,
        address,
    } = factor;
    let Some(code) = code.filter(|c| !c.trim().is_empty()) else {
        login_audit(
            state,
            canonical,
            "login.second_factor",
            "right password; asked for the two-factor code",
            address,
        )
        .await?;
        return Err(
            ApiError::unauthorized("Enter the 6-digit code from your authenticator app.")
                .with("totpRequired", json!(true)),
        );
    };
    let bad_code = || {
        ApiError::unauthorized("That code is not right. Codes change every 30 seconds.")
            .with("totpRequired", json!(true))
    };
    let Some(step) = auth::verify_totp(&secret, &code, last_step) else {
        login_audit(
            state,
            canonical,
            "login.failed",
            "right password, wrong two-factor code",
            address,
        )
        .await?;
        return Err(bad_code());
    };
    // Only one sign-in may consume a given code, even when two race.
    let id = user_id.to_owned();
    let claimed = state
        .db
        .call(move |c| {
            Ok(c.execute(
                "UPDATE users SET totp_last_step = ?2 WHERE id = ?1 AND totp_last_step < ?2",
                rusqlite::params![id, step],
            )? == 1)
        })
        .await?;
    if !claimed {
        login_audit(
            state,
            canonical,
            "login.failed",
            "right password, reused two-factor code",
            address,
        )
        .await?;
        return Err(bad_code());
    }
    Ok(())
}

async fn finish_login(
    state: Shared,
    attempt: LoginAttempt,
    headers: HeaderMap,
) -> ApiResult<axum::http::HeaderValue> {
    let LoginAttempt {
        username,
        password,
        totp_code,
        address,
        address_key,
        user_key,
    } = attempt;
    let user = state
        .db
        .call(move |c| {
            Ok(c.query_row(
                "SELECT id, username, password_hash, totp_secret, totp_enabled, totp_last_step
                 FROM users WHERE username = ?1",
                [username],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, bool>(4)?,
                        r.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()?)
        })
        .await?;

    // Unknown users cost the same Argon2 work as real ones.
    let hash = user.as_ref().map(|u| u.2.clone());
    let password_ok = state
        .hashing(move || match &hash {
            Some(hash) => auth::verify_password(&password, hash),
            None => auth::verify_password(&password, auth::dummy_hash()),
        })
        .await?;
    let wrong = || ApiError::unauthorized("Wrong username or password.");
    let Some((user_id, canonical, _, totp_secret, totp_enabled, last_step)) = user else {
        return Err(wrong());
    };
    if !password_ok {
        login_audit(
            &state,
            &canonical,
            "login.failed",
            "wrong password",
            &address,
        )
        .await?;
        return Err(wrong());
    }

    if totp_enabled {
        let factor = SecondFactor {
            user_id: &user_id,
            canonical: &canonical,
            secret: totp_secret.unwrap_or_default(),
            last_step,
            address: &address,
        };
        second_factor(&state, factor, totp_code).await?;
    }

    state.login_limiter.record_success(&address_key);
    state.login_limiter.record_success(&user_key);
    login_audit(&state, &canonical, "login", "", &address).await?;
    session::start_session(&state, user_id, &headers, address).await
}

pub async fn logout(
    State(state): State<Shared>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    if let Some(token) = session::session_cookie(&headers) {
        let hash = auth::session_hash(&token);
        state
            .db
            .call(move |c| {
                c.execute("DELETE FROM sessions WHERE token_hash = ?1", [hash])?;
                Ok(())
            })
            .await?;
        state.hub.end_session(&hash);
    }
    Ok(([session::clear_cookie()], Json(json!({ "ok": true }))))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasswordRequest {
    current_password: String,
    new_password: String,
}

async fn check_password(state: &Shared, user: &CurrentUser, password: String) -> ApiResult<()> {
    let key = format!("user:{}", user.username.to_ascii_lowercase());
    // Counted before hashing, like sign-in.
    state
        .login_limiter
        .attempt(&key)
        .map_err(ApiError::too_many)?;
    if password.len() > auth::MAX_PASSWORD_BYTES {
        return Err(ApiError::forbidden("Your current password is not right."));
    }
    let id = user.id.clone();
    let hash: String = state
        .db
        .call(move |c| {
            Ok(
                c.query_row("SELECT password_hash FROM users WHERE id = ?1", [id], |r| {
                    r.get(0)
                })?,
            )
        })
        .await?;
    if !state
        .hashing(move || auth::verify_password(&password, &hash))
        .await?
    {
        return Err(ApiError::forbidden("Your current password is not right."));
    }
    state.login_limiter.record_success(&key);
    Ok(())
}

/// Changes the password and signs out every other session.
pub async fn change_password(
    State(state): State<Shared>,
    user: CurrentUser,
    Json(body): Json<PasswordRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    check_password(&state, &user, body.current_password).await?;
    auth::validate_password(&body.new_password, &user.username).map_err(ApiError::bad_request)?;
    let password = body.new_password;
    let hash = state
        .hashing(move || auth::hash_password(&password))
        .await??;
    let CurrentUser {
        id,
        username,
        session_hash,
        address,
        ..
    } = user;
    let user_id = id.clone();
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            tx.execute(
                "UPDATE users SET password_hash = ?2 WHERE id = ?1",
                rusqlite::params![id, hash],
            )?;
            tx.execute(
                "DELETE FROM sessions WHERE user_id = ?1 AND token_hash != ?2",
                rusqlite::params![id, session_hash],
            )?;
            db::audit(
                &tx,
                &username,
                "account.password_changed",
                &username,
                "",
                &address,
            )?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    state.hub.end_user_sessions(&user_id, Some(&session_hash));
    Ok(Json(json!({ "ok": true })))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpSetup {
    secret: String,
    uri: String,
    qr_svg: String,
}

/// Starts two-factor setup: a fresh secret that is not active until a code
/// from it is confirmed.
pub async fn totp_setup(
    State(state): State<Shared>,
    user: CurrentUser,
) -> ApiResult<Json<TotpSetup>> {
    if user.totp_enabled {
        return Err(ApiError::conflict("Two-factor sign-in is already on."));
    }
    let secret = auth::new_totp_secret();
    let uri = auth::totp_uri(&user.username, &secret);
    let qr_svg = qrcode::QrCode::new(uri.as_bytes())
        .map(|code| {
            code.render::<qrcode::render::svg::Color<'_>>()
                .min_dimensions(200, 200)
                .quiet_zone(true)
                .build()
        })
        .map_err(|e| anyhow::anyhow!("qr: {e}"))?;
    let id = user.id.clone();
    let stored = secret.clone();
    state
        .db
        .call(move |c| {
            c.execute(
                "UPDATE users SET totp_secret = ?2 WHERE id = ?1 AND totp_enabled = 0",
                rusqlite::params![id, stored],
            )?;
            Ok(())
        })
        .await?;
    Ok(Json(TotpSetup {
        secret,
        uri,
        qr_svg,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TotpEnableRequest {
    code: String,
    /// Current password: a borrowed session alone must not be able to lock
    /// the owner out with a second factor.
    password: String,
}

pub async fn totp_enable(
    State(state): State<Shared>,
    user: CurrentUser,
    Json(body): Json<TotpEnableRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    check_password(&state, &user, body.password).await?;
    let id = user.id.clone();
    let secret: Option<String> = state
        .db
        .call(move |c| {
            Ok(
                c.query_row("SELECT totp_secret FROM users WHERE id = ?1", [id], |r| {
                    r.get(0)
                })?,
            )
        })
        .await?;
    let secret = secret.ok_or_else(|| ApiError::bad_request("Start two-factor setup first."))?;
    let step = auth::verify_totp(&secret, &body.code, 0).ok_or_else(|| {
        ApiError::bad_request("That code is not right. Check the time on your phone and try again.")
    })?;
    let CurrentUser {
        id,
        username,
        address,
        ..
    } = user;
    state
        .db
        .call(move |c| {
            c.execute(
                "UPDATE users SET totp_enabled = 1, totp_last_step = ?2 WHERE id = ?1",
                rusqlite::params![id, step],
            )?;
            db::audit(
                c,
                &username,
                "account.totp_enabled",
                &username,
                "",
                &address,
            )?;
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TotpDisableRequest {
    password: String,
}

pub async fn totp_disable(
    State(state): State<Shared>,
    user: CurrentUser,
    Json(body): Json<TotpDisableRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    check_password(&state, &user, body.password).await?;
    let CurrentUser {
        id,
        username,
        address,
        ..
    } = user;
    state
        .db
        .call(move |c| {
            c.execute(
                "UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?1",
                [&id],
            )?;
            db::audit(
                c,
                &username,
                "account.totp_disabled",
                &username,
                "",
                &address,
            )?;
            Ok(())
        })
        .await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperatorView {
    id: String,
    username: String,
    totp_enabled: bool,
    created_at: i64,
}

pub async fn list_users(
    State(state): State<Shared>,
    _user: CurrentUser,
) -> ApiResult<Json<Vec<OperatorView>>> {
    let users = state
        .db
        .call(|c| {
            let mut statement = c.prepare(
                "SELECT id, username, totp_enabled, created_at FROM users ORDER BY username",
            )?;
            let rows = statement
                .query_map([], |r| {
                    Ok(OperatorView {
                        id: r.get(0)?,
                        username: r.get(1)?,
                        totp_enabled: r.get(2)?,
                        created_at: r.get(3)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await?;
    Ok(Json(users))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateUserRequest {
    username: String,
    password: String,
}

pub async fn create_user(
    State(state): State<Shared>,
    user: CurrentUser,
    Json(body): Json<CreateUserRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let username = body.username.trim().to_owned();
    auth::validate_username(&username).map_err(ApiError::bad_request)?;
    auth::validate_password(&body.password, &username).map_err(ApiError::bad_request)?;
    let password = body.password;
    let hash = state
        .hashing(move || auth::hash_password(&password))
        .await??;
    let id = uuid::Uuid::new_v4().to_string();
    let created_id = id.clone();
    let inserted = state
        .db
        .call(move |c| {
            let changed = c.execute(
                "INSERT INTO users (id, username, password_hash, created_at)
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT (username) DO NOTHING",
                rusqlite::params![created_id, username, hash, now()],
            )?;
            if changed == 1 {
                db::audit(
                    c,
                    &user.username,
                    "user.created",
                    &username,
                    "",
                    &user.address,
                )?;
            }
            Ok(changed == 1)
        })
        .await?;
    if !inserted {
        return Err(ApiError::conflict("Someone already has that username."));
    }
    Ok((StatusCode::CREATED, Json(json!({ "id": id }))))
}

pub async fn delete_user(
    State(state): State<Shared>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    if id == user.id {
        return Err(ApiError::bad_request("You cannot remove your own account."));
    }
    let target = id.clone();
    let removed = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            // Checked inside the transaction: two operators removing each
            // other at once must not leave zero accounts.
            let actor: bool = tx
                .query_row("SELECT 1 FROM users WHERE id = ?1", [&user.id], |_| Ok(()))
                .optional()?
                .is_some();
            if !actor {
                return Ok(Err(ApiError::unauthorized(
                    "Your account was removed. Sign in with another account.",
                )));
            }
            let count: i64 = tx.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
            if count <= 1 {
                return Ok(Err(ApiError::conflict(
                    "The last account cannot be removed.",
                )));
            }
            let name: Option<String> = tx
                .query_row("SELECT username FROM users WHERE id = ?1", [&id], |r| {
                    r.get(0)
                })
                .optional()?;
            let Some(name) = name else {
                return Ok(Ok(false));
            };
            tx.execute("DELETE FROM users WHERE id = ?1", [&id])?;
            db::audit(
                &tx,
                &user.username,
                "user.removed",
                &name,
                "",
                &user.address,
            )?;
            tx.commit()?;
            Ok(Ok(true))
        })
        .await??;
    if !removed {
        return Err(ApiError::not_found("That operator no longer exists."));
    }
    state.hub.end_user_sessions(&target, None);
    Ok(Json(json!({ "ok": true })))
}
