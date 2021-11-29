mod forward;

use std::collections::HashMap;

use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    algorithms::AnonCryptAlg,
    did::{DIDCommMessagingService, DIDResolver, Service, ServiceKind},
    error::{err_msg, ErrorKind, Result, ResultContext, ResultExt},
    message::{anoncrypt, MessagingServiceMetadata},
    utils::did::{did_or_url, is_did},
    Attachment, AttachmentData, Message, PackEncryptedOptions,
};

pub use self::forward::ParsedForward;

pub(crate) const FORWARD_MSG_TYPE: &str = "https://didcomm.org/routing/2.0/forward";

pub(crate) const DIDCOMM_V2_PROFILE: &str = "didcomm/v2";

async fn find_did_comm_service<'dr>(
    did: &str,
    service_id: Option<&str>,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
) -> Result<Option<(String, DIDCommMessagingService)>> {
    let did_doc = did_resolver
        .resolve(did)
        .await
        .context("Unable resolve DID")?
        .ok_or_else(|| err_msg(ErrorKind::DIDNotResolved, "DID not found"))?;

    match service_id {
        Some(service_id) => {
            let service: &Service = did_doc
                .services
                .iter()
                .find(|&service| service.id == service_id)
                .ok_or_else(|| {
                    err_msg(
                        ErrorKind::IllegalArgument,
                        "Service with the specified ID not found",
                    )
                })?;

            match service.kind {
                ServiceKind::DIDCommMessaging { ref value } => {
                    if value.accept.contains(&DIDCOMM_V2_PROFILE.into()) {
                        Ok(Some((service.id.clone(), value.clone())))
                    } else {
                        Err(err_msg(
                            ErrorKind::IllegalArgument,
                            "Service with the specified ID does not accept didcomm/v2 profile",
                        ))
                    }
                }
                _ => Err(err_msg(
                    ErrorKind::IllegalArgument,
                    "Service with the specified ID is not of DIDCommMessaging type",
                )),
            }
        }

        None => Ok(did_doc
            .services
            .iter()
            .find_map(|service| match service.kind {
                ServiceKind::DIDCommMessaging { ref value }
                    if value.accept.contains(&DIDCOMM_V2_PROFILE.into()) =>
                {
                    Some((service.id.clone(), value.clone()))
                }
                _ => None,
            })),
    }
}

async fn resolve_did_comm_services_chain<'dr>(
    to: &str,
    service_id: Option<&str>,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
) -> Result<Vec<(String, DIDCommMessagingService)>> {
    let (to_did, _) = did_or_url(to);

    let service = find_did_comm_service(to_did, service_id, did_resolver).await?;

    if service.is_none() {
        return Ok(vec![]);
    }

    let mut service = service.unwrap();

    let mut services = vec![service.clone()];
    let mut service_endpoint = &service.1.service_endpoint;

    while is_did(service_endpoint) {
        // Now alternative endpoints recursion is not supported
        // (because it should not be used according to the specification)
        if services.len() > 1 {
            return Err(err_msg(
                ErrorKind::InvalidState,
                "DID doc defines alternative endpoints recursively",
            ));
        }

        service = find_did_comm_service(service_endpoint, None, did_resolver)
            .await?
            .ok_or_else(|| {
                err_msg(
                    // TODO: Think on introducing a more appropriate error kind
                    ErrorKind::InvalidState,
                    "Referenced mediator does not provide any DIDCommMessaging services",
                )
            })?;

        services.insert(0, service.clone());
        service_endpoint = &service.1.service_endpoint;
    }

    Ok(services)
}

fn generate_message_id() -> String {
    Uuid::new_v4().to_string()
}

fn build_forward_message(
    forwarded_msg: &str,
    next: &str,
    headers: Option<&HashMap<String, Value>>,
) -> Result<String> {
    let body = json!({ "next": next });

    // TODO: Think how to avoid extra deserialization of forwarded_msg here.
    // (This deserializtion is a double work because the whole Forward message with the attachments
    // will then be serialized.)
    let attachment = Attachment::json(
        serde_json::from_str(forwarded_msg)
            .kind(ErrorKind::Malformed, "Unable deserialize forwarded message")?,
    )
    .finalize();

    let mut msg_builder = Message::build(generate_message_id(), FORWARD_MSG_TYPE.to_owned(), body);

    if let Some(headers) = headers {
        for (name, value) in headers {
            msg_builder = msg_builder.header(name.to_owned(), value.to_owned());
        }
    }

    msg_builder = msg_builder.attachment(attachment);

    let msg = msg_builder.finalize();

    serde_json::to_string(&msg).kind(ErrorKind::InvalidState, "Unable serialize forward message")
}

/// Tries to parse plaintext message into `ParsedForward` structure if the message is Forward.
/// (https://identity.foundation/didcomm-messaging/spec/#messages)
///
/// # Parameters
/// - `msg` plaintext message to try to parse into `ParsedForward` structure
///
/// # Returns
/// `Some` with `ParsedForward` structure if `msg` is Forward message, otherwise `None`.
pub fn try_parse_forward(msg: &Message) -> Option<ParsedForward> {
    if msg.type_ != FORWARD_MSG_TYPE {
        return None;
    }

    let next = match msg.body {
        Value::Object(ref body) => match body.get("next") {
            Some(&Value::String(ref next)) => Some(next),
            _ => None,
        },
        _ => None,
    };

    if next.is_none() {
        return None;
    }

    let next = next.unwrap();

    let json_attachment_data = match msg.attachments {
        Some(ref attachments) => match &attachments[..] {
            [attachment, ..] => match &attachment.data {
                AttachmentData::Json { ref value } => Some(value),
                _ => None,
            },
            _ => None,
        },
        None => None,
    };

    if json_attachment_data.is_none() {
        return None;
    }

    let forwarded_msg = &json_attachment_data.unwrap().json;

    Some(ParsedForward {
        msg,
        next: next.clone(),
        forwarded_msg: forwarded_msg.clone(),
    })
}

/// Wraps an anoncrypt or authcrypt message into a Forward onion (nested Forward messages).
/// https://identity.foundation/didcomm-messaging/spec/#messages
///
/// # Parameters
/// - `msg` Anoncrypt or authcrypt message to wrap into Forward onion.
/// - `headers` (optional) Additional headers to each Forward message of the onion.
/// - `to` Recipient (a key identifier or DID) of the message being wrapped into Forward onion.
/// - `routing_keys` Routing keys (each one is a key identifier or DID) to use for encryption of
/// Forward messages in the onion. The keys must be ordered along the route (so in the opposite
/// direction to the wrapping steps).
/// - `enc_alg_anon` Algorithm to use for wrapping into each Forward message of the onion.
/// - `did_resolver` instance of `DIDResolver` to resolve DIDs.
///
/// # Returns
/// `Result` with the message wrapped into Forward onion or `Error`.
///
/// # Errors
/// - `Malformed` The message to wrap is malformed.
/// - `DIDNotResolved` Issuer DID not found.
/// - `DIDUrlNotFound` Issuer authentication verification method is not found.
/// - `Unsupported` Used crypto or method is unsupported.
/// - `InvalidState` Indicates a library error.
pub async fn wrap_in_forward<'dr>(
    msg: &str,
    headers: Option<&HashMap<String, Value>>,
    to: &str,
    routing_keys: &Vec<String>,
    enc_alg_anon: &AnonCryptAlg,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
) -> Result<String> {
    let mut tos = routing_keys.clone();

    let mut nexts = tos.clone();
    nexts.remove(0);
    nexts.push(to.to_owned());

    tos.reverse();
    nexts.reverse();

    let mut msg = msg.to_owned();

    for (to_, next_) in tos.iter().zip(nexts.iter()) {
        msg = build_forward_message(&msg, next_, headers)?;
        msg = anoncrypt(to_, did_resolver, msg.as_bytes(), enc_alg_anon)
            .await?
            .0;
    }

    Ok(msg)
}

pub(crate) async fn wrap_in_forward_if_needed<'dr>(
    msg: &str,
    to: &str,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
    options: &PackEncryptedOptions,
) -> Result<Option<(String, MessagingServiceMetadata)>> {
    if !options.forward {
        return Ok(None);
    }

    let services_chain =
        resolve_did_comm_services_chain(to, options.messaging_service.as_deref(), did_resolver)
            .await?;

    if services_chain.is_empty() {
        return Ok(None);
    }

    let mut routing_keys = services_chain[1..]
        .iter()
        .map(|service| service.1.service_endpoint.clone())
        .collect::<Vec<_>>();

    routing_keys.append(&mut services_chain.last().unwrap().1.routing_keys.clone());

    if routing_keys.is_empty() {
        return Ok(None);
    }

    let forward_msg = wrap_in_forward(
        msg,
        options.forward_headers.as_ref(),
        to,
        &routing_keys,
        &options.enc_alg_anon,
        did_resolver,
    )
    .await?;

    let messaging_service = MessagingServiceMetadata {
        id: services_chain.last().unwrap().0.clone(),
        service_endpoint: services_chain.first().unwrap().1.service_endpoint.clone(),
    };

    Ok(Some((forward_msg, messaging_service)))
}
