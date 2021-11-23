export const PLAINTEXT_MSG_SIMPLE = `
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
`;

export const PLAINTEXT_MSG_MINIMAL = `
{
    "id": "1234567890",
    "typ": "application/didcomm-plain+json",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    "body": {}
}
`;

export const PLAINTEXT_FROM_PRIOR = `
{
    "id": "1234567890",
    "typ": "application/didcomm-plain+json",
    "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
    "from": "did:example:alice",
    "to": ["did:example:bob"],
    "created_time": 1516269022,
    "expires_time": 1516385931,
    "from_prior": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpleGFtcGxlOmNoYXJsaWUja2V5LTEifQ.eyJpc3MiOiJkaWQ6ZXhhbXBsZTpjaGFybGllIiwic3ViIjoiZGlkOmV4YW1wbGU6YWxpY2UiLCJhdWQiOiIxMjMiLCJleHAiOjEyMzQsIm5iZiI6MTIzNDUsImlhdCI6MTIzNDU2LCJqdGkiOiJkZmcifQ.ir0tegXiGJIZIMagO5P853KwhzGTEw0OpFFAyarUV-nQrtbI_ELbxT9l7jPBoPve_-60ifGJ9v3ArmFjELFlDA",
    "body": {"messagespecificattribute": "and its value"}
}
`;
