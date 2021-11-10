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

pub(crate) const INVALID_PLAINTEXT_MSG_EMPTY: &str = r#"
{}
"#;

pub(crate) const INVALID_PLAINTEXT_MSG_STRING: &str = r#"
aaaa
"#;

pub(crate) const INVALID_PLAINTEXT_MSG_NO_ID: &str = r#"
{
    "typ": "application/didcomm-plain+json",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    "body": {}
}
"#;

pub(crate) const INVALID_PLAINTEXT_MSG_NO_TYP: &str = r#"
{
    "id": "1234567890",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    "body": {}
}
"#;

pub(crate) const INVALID_PLAINTEXT_MSG_NO_TYPE: &str = r#"
{
    "id": "1234567890",
    "typ": "application/didcomm-plain+json",
    "body": {}
}
"#;

pub(crate) const INVALID_PLAINTEXT_MSG_NO_BODY: &str = r#"
{
    "id": "1234567890",
    "typ": "application/didcomm-plain+json",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal"
}
"#;

pub(crate) const INVALID_PLAINTEXT_MSG_WRONG_TYP: &str = r#"
{
    "id": "1234567890",
    "typ": "application/didcomm-plain+json-unknown",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    "body": {}
}
"#;

pub(crate) const INVALID_PLAINTEXT_MSG_EMPTY_ATTACHMENTS: &str = r#"
{
    "id": "1234567890",
    "typ": "application/didcomm-plain+json",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    "body": {},
    "attachments": [{}]
}
"#;

pub(crate) const INVALID_PLAINTEXT_MSG_ATTACHMENTS_NO_DATA: &str = r#"
{
    "id": "1234567890",
    "typ": "application/didcomm-plain+json",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    "body": {},
    "attachments": [{"id": "23"}]
}
"#;

pub(crate) const INVALID_PLAINTEXT_MSG_ATTACHMENTS_EMPTY_DATA: &str = r#"
{
    "id": "1234567890",
    "typ": "application/didcomm-plain+json",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    "body": {},
    "attachments": [{"id": "23", "data": {}}]
}
"#;

pub(crate) const INVALID_PLAINTEXT_MSG_ATTACHMENTS_LINKS_NO_HASH: &str = r#"
{
    "id": "1234567890",
    "typ": "application/didcomm-plain+json",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    "body": {},
    "attachments": [{"id": "23", "data": {"links": ["231", "212"]}}]
}
"#;

pub(crate) const INVALID_PLAINTEXT_MSG_ATTACHMENTS_AS_STRING: &str = r#"
{
    "id": "1234567890",
    "typ": "application/didcomm-plain+json",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    "body": {},
    "attachments": "131"
}
"#;

pub(crate) const INVALID_PLAINTEXT_MSG_ATTACHMENTS_AS_INT_ARRAY: &str = r#"
{
    "id": "1234567890",
    "typ": "application/didcomm-plain+json",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    "body": {},
    "attachments": [2131]
}
"#;

pub(crate) const INVALID_PLAINTEXT_MSG_ATTACHMENTS_WRONG_DATA: &str = r#"
{
    "id": "1234567890",
    "typ": "application/didcomm-plain+json",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    "body": {},
    "attachments": [{"id": "1", "data": "invalid"}]
}
"#;

pub(crate) const INVALID_PLAINTEXT_MSG_ATTACHMENTS_WRONG_ID: &str = r#"
{
    "id": "1234567890",
    "typ": "application/didcomm-plain+json",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    "body": {},
    "attachments": [{"id": 2}]
}
"#;

pub(crate) const INVALID_PLAINTEXT_MSG_ATTACHMENTS_NULL_DATA: &str = r#"
{
    "id": "1234567890",
    "typ": "application/didcomm-plain+json",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    "body": {},
    "attachments": [{"id": "1", "data": null}]
}
"#;
