pub(crate) const PLAINTEXT_MSG_SIMPLE: &str = r#"
{
    "id": "1234567890",
    "typ": "application/didcomm-plain+json",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    "from": "did:example:alice",
    "to": ["did:example:bob"],
    "created_time": 1516269022,
    "expires_time": 1516385931,
    "body": {"messagespecificattribute": "and its value"}
}
"#;

pub(crate) const PLAINTEXT_MSG_MINIMAL: &str = r#"
{
    "id": "1234567890",
    "typ": "application/didcomm-plain+json",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    "body": {}
}
"#;

pub(crate) const PLAINTEXT_MSG_ATTACHMENT_BASE64: &str = r#"
{
    "id": "1234567890",
    "typ": "application/didcomm-plain+json",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    "from": "did:example:alice",
    "to": ["did:example:bob"],
    "created_time": 1516269022,
    "expires_time": 1516385931,
    "body": {"messagespecificattribute": "and its value"},
    "attachments": [{"id": "23", "data": {"base64": "qwerty"}}]
}
"#;

pub(crate) const PLAINTEXT_MSG_ATTACHMENT_LINKS: &str = r#"
{
    "id": "1234567890",
    "typ": "application/didcomm-plain+json",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    "from": "did:example:alice",
    "to": ["did:example:bob"],
    "created_time": 1516269022,
    "expires_time": 1516385931,
    "body": {"messagespecificattribute": "and its value"},
    "attachments": [
        {"id": "23", "data": {"links": ["1", "2", "3"], "hash": "qwerty"}}
    ]
}
"#;

pub(crate) const PLAINTEXT_MSG_ATTACHMENT_JSON: &str = r#"
{
    "id": "1234567890",
    "typ": "application/didcomm-plain+json",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    "from": "did:example:alice",
    "to": ["did:example:bob"],
    "created_time": 1516269022,
    "expires_time": 1516385931,
    "body": {"messagespecificattribute": "and its value"},
    "attachments": [
        {"id": "23", "data": {"json": {"foo": "bar", "links": [2, 3]}}}
    ]
}
"#;

pub(crate) const PLAINTEXT_MSG_ATTACHMENT_MULTI_1: &str = r#"
{
    "id": "1234567890",
    "typ": "application/didcomm-plain+json",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    "from": "did:example:alice",
    "to": ["did:example:bob"],
    "created_time": 1516269022,
    "expires_time": 1516385931,
    "body": {"messagespecificattribute": "and its value"},
    "attachments": [
        {"id": "23", "data": {"json": {"foo": "bar", "links": [2, 3]}}},
        {"id": "24", "data": {"base64": "qwerty"}},
        {"id": "25", "data": {"links": ["1", "2", "3"], "hash": "qwerty"}}
    ]
}
"#;

pub(crate) const PLAINTEXT_MSG_ATTACHMENT_MULTI_2: &str = r#"
{
    "id": "1234567890",
    "typ": "application/didcomm-plain+json",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    "from": "did:example:alice",
    "to": ["did:example:bob"],
    "created_time": 1516269022,
    "expires_time": 1516385931,
    "body": {"messagespecificattribute": "and its value"},
    "attachments": [
        {"id": "23", "data": {"links": ["1", "2", "3"], "hash": "qwerty"}},
        {"id": "24", "data": {"base64": "qwerty"}},
        {"id": "25", "data": {"links": ["1", "2", "3", "4"], "hash": "qwerty2"}}
    ]
}
"#;
