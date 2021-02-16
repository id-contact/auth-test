use rocket::{get, launch, post, response::Redirect, routes, State, request::Form, request::FromForm};
use rocket_contrib::json::Json;
use serde::Deserialize;
use std::{error::Error as StdError, fmt::Display, fs::File};

mod config;
mod idauth;
mod jwe;

#[derive(Debug)]
enum Error {
    Config(config::Error),
    Decode(base64::DecodeError),
    Json(serde_json::Error),
    Utf(std::str::Utf8Error),
    JWT(jwe::Error),
}

impl<'r, 'o: 'r> rocket::response::Responder<'r, 'o> for Error {
    fn respond_to(self, request: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        let debug_error = rocket::response::Debug::from(self);
        debug_error.respond_to(request)
    }
}

impl From<config::Error> for Error {
    fn from(e: config::Error) -> Error {
        Error::Config(e)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Error {
        Error::Decode(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::Json(e)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Error {
        Error::Utf(e)
    }
}

impl From<jwe::Error> for Error {
    fn from(e: jwe::Error) -> Error {
        Error::JWT(e)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Config(e) => e.fmt(f),
            Error::Decode(e) => e.fmt(f),
            Error::Utf(e) => e.fmt(f),
            Error::Json(e) => e.fmt(f),
            Error::JWT(e) => e.fmt(f),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Config(e) => Some(e),
            Error::Decode(e) => Some(e),
            Error::Utf(e) => Some(e),
            Error::Json(e) => Some(e),
            Error::JWT(e) => Some(e),
        }
    }
}

#[derive(FromForm, Debug)]
struct SessionUpdateData {
    #[form(field="type")]
    typeval: String
}

#[post("/session/update?<typedata..>")]
async fn session_update(typedata: Form<SessionUpdateData>) {
    println!("Session update received: {}", typedata.typeval);
}

#[get("/browser/<attributes>/<continuation>/<attr_url>")]
async fn user_oob(config: State<'_, config::Config>, attributes: String, continuation: String, attr_url: String) -> Result<Redirect, Error> {
    let attributes = base64::decode(attributes)?;
    let attributes: Vec<String> = serde_json::from_slice(&attributes)?;
    let attributes = config.map_attributes(&attributes)?;
    let attributes = jwe::sign_and_encrypt_attributes(&attributes, config.signer(), config.encrypter())?;

    let continuation = base64::decode(continuation)?;
    let continuation = std::str::from_utf8(&continuation)?;

    let attr_url = base64::decode(attr_url)?;
    let attr_url = std::str::from_utf8(&attr_url)?;

    let mut session_url = None;
    if config.with_session() {
        session_url = Some(format!("{}/session/update", config.server_url()));
    }

    let client = reqwest::Client::new();
    let result = client
        .post(attr_url)
        .json(&idauth::AuthResult {
            status: idauth::AuthStatus::Succes,
            attributes: Some(attributes.clone()),
            session_url,
        })
        .send()
        .await;
    if let Err(e) = result {
        // Log only
        println!("Failure reporting results: {}", e);
    } else {
        println!("Reported result jwe {} to {}", &attributes, attr_url);
    }

    println!("Redirecting user to {}", continuation);
    Ok(Redirect::to(continuation.to_string()))
}

#[get("/browser/<attributes>/<continuation>")]
async fn user_inline(config: State<'_, config::Config>, attributes: String, continuation: String) -> Result<Redirect, Error> {
    let attributes = base64::decode(attributes)?;
    let attributes: Vec<String> = serde_json::from_slice(&attributes)?;
    let attributes = config.map_attributes(&attributes)?;
    let attributes = jwe::sign_and_encrypt_attributes(&attributes, config.signer(), config.encrypter())?;

    let continuation = base64::decode(continuation)?;
    let continuation = std::str::from_utf8(&continuation)?;

    println!("Redirecting user to {} with attribute result {}", continuation, &attributes);

    if config.with_session() {
        let session_url = urlencoding::encode(&format!("{}/session/update", config.server_url()));
        Ok(Redirect::to(format!("{}?status=succes&attributes={}&session_url={}", continuation, attributes, session_url)))
    } else {
        Ok(Redirect::to(format!("{}?status=succes&attributes={}", continuation, attributes)))
    }
}

#[post("/start_authentication", data = "<request>")]
async fn start_authentication(
    config: State<'_, config::Config>,
    request: Json<idauth::AuthRequest>,
) -> Result<Json<idauth::StartAuthResponse>, Error> {
    config.verify_attributes(&request.attributes)?;

    let attributes = base64::encode(serde_json::to_vec(&request.attributes)?);
    let continuation = base64::encode(&request.continuation);

    if let Some(attr_url) = &request.attr_url {
        let attr_url = base64::encode(attr_url);

        Ok(Json(idauth::StartAuthResponse {
            client_url: format!("{}/browser/{}/{}/{}",
                config.server_url(),
                attributes,
                continuation,
                attr_url,
            ),
        }))
    } else {
        Ok(Json(idauth::StartAuthResponse {
            client_url: format!("{}/browser/{}/{}",
                config.server_url(),
                attributes,
                continuation,
            ),
        }))
    }
}

#[launch]
fn rocket() -> rocket::Rocket {
    let configfile = File::open(std::env::var("CONFIG").expect("No configuration file specified"))
        .expect("Could not open configuration");
    rocket::ignite()
        .mount(
            "/",
            routes![
                start_authentication,
                user_inline,
                user_oob,
                session_update,
            ],
        )
        .manage(config::Config::from_reader(&configfile).expect("Could not read configuration"))
}
