mod forward;

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

async fn find_did_comm_service<'dr>(
    did: &str,
    service_id: Option<&str>,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
) -> Result<Option<Service>> {
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
                        ErrorKind::InvalidState,
                        "Service with the specified ID not found",
                    )
                })?;

            if let ServiceKind::DIDCommMessaging(_) = service.kind {
                Ok(Some(service.clone()))
            } else {
                Err(err_msg(
                    ErrorKind::InvalidState,
                    "Service with the specified ID is not of DIDCommMessaging type",
                ))
            }
        }

        None => Ok(did_doc.services.iter().find_map(|service| {
            if let ServiceKind::DIDCommMessaging(_) = service.kind {
                Some(service.clone())
            } else {
                None
            }
        })),
    }
}

fn unwrap_did_comm_service(service: &Service) -> Result<&DIDCommMessagingService> {
    match service.kind {
        ServiceKind::DIDCommMessaging(ref did_comm_service) => Ok(did_comm_service),
        ServiceKind::Other(_) => Err(err_msg(
            ErrorKind::InvalidState,
            "Service is not of DIDCommMessaging type",
        )),
    }
}

async fn resolve_did_comm_services_chain<'dr>(
    to: &str,
    service_id: Option<&str>,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
) -> Result<Vec<Service>> {
    let (to_did, _) = did_or_url(to);

    let service = find_did_comm_service(to_did, service_id, did_resolver).await?;

    if service.is_none() {
        return Ok(vec![]);
    }

    let mut service = service.unwrap();

    let mut services = vec![service.clone()];
    let mut service_endpoint = &unwrap_did_comm_service(&service)?.service_endpoint;

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
                    ErrorKind::InvalidState,
                    "Referenced mediator does not provide any DIDCommMessaging services",
                )
            })?;
        services.insert(0, service.clone());
        service_endpoint = &unwrap_did_comm_service(&service)?.service_endpoint;
    }

    Ok(services)
}

fn generate_message_id() -> String {
    Uuid::new_v4().to_string()
}

fn build_forward_message(
    forwarded_msg: &str,
    next: &str,
    headers: Option<&Vec<(String, Value)>>,
) -> Result<String> {
    let body = json!({ "next": next });

    let attachment = Attachment::json(serde_json::from_str(forwarded_msg)?).finalize();

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
                AttachmentData::Json(forwarded_msg_data) => Some(forwarded_msg_data),
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
        msg: msg.clone(),
        next: next.clone(),
        forwarded_msg: forwarded_msg.clone(),
    })
}

pub async fn wrap_in_forward<'dr>(
    msg: &str,
    headers: Option<&Vec<(String, Value)>>,
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
        .map(|service| unwrap_did_comm_service(service))
        .collect::<Result<Vec<_>>>()?
        .iter()
        .map(|did_comm_service| did_comm_service.service_endpoint.clone())
        .collect::<Vec<_>>();

    routing_keys.append(
        &mut unwrap_did_comm_service(services_chain.last().unwrap())?
            .routing_keys
            .clone(),
    );

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
        id: services_chain.last().unwrap().id.clone(),
        service_endpoint: unwrap_did_comm_service(services_chain.first().unwrap())?
            .service_endpoint
            .clone(),
    };

    Ok(Some((forward_msg, messaging_service)))
}
