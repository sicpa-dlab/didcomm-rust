pub(crate) const ENCRYPTED_MSG_ANON_XC20P_1: &str = r#"
{
    "ciphertext": "KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p",
    "protected": "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
    "recipients": [{
            "encrypted_key": "3n1olyBR3nY7ZGAprOx-b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1A",
            "header": {
                "kid": "did:example:bob#key-x25519-1"
            }
        },{
            "encrypted_key": "j5eSzn3kCrIkhQAWPnEwrFPMW6hG0zF_y37gUvvc5gvlzsuNX4hXrQ",
            "header": {
                "kid": "did:example:bob#key-x25519-2"
            }
        },{
            "encrypted_key": "TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItfwmNyDm73A",
            "header": {
                "kid": "did:example:bob#key-x25519-3"
            }
        }],
    "tag": "6ylC_iAs4JvDQzXeY6MuYQ",
    "iv": "ESpmcyGiZpRjc5urDela21TOOTW8Wqd1"
}
"#;

pub(crate) const ENCRYPTED_MSG_ANON_XC20P_2: &str = r#"
{
    "ciphertext": "912eTUDRKTzhUUqxosPogT1bs9w9wv4s4HmoWkaeU9Uj92V4ENpk-_ZPNSvPyXYLfFj0nc9V2-ux5jq8hqUd17WJpXEM1ReMUjtnTqeUzVa7_xtfkbfhaOZdL8OfgNquPDH1bYcBshN9O9lMT0V52gmGaAB45k4I2PNHcc0A5XWzditCYi8wOkPDm5A7pA39Au5uUNiFQjRYDrz1YvJwV9cdca54vYsBfV1q4c8ncQsv5tNnFYQ1s4rAG7RbyWdAjkC89kE_hIoRRkWZhFyNSfdvRtlUJDlM19uml7lwBWWPnqkmQ3ubiBGmVct3pjrcDvjissOw8Dwkn4E1V1gafec-jDBy4Rndai_RdGjnXjMJs7nRv3Ot",
    "protected": "eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJFczdpUDNFaExDSGxBclAwS2NZRmNxRXlCYXByMks2WU9BOVc4ZU84YXU4IiwieSI6Ik42QWw3RVR3Q2RwQzZOamRlY3IyS1hBZzFVZVp5X3VmSFJRS3A5RzZLR2sifSwiYXB2Ijoiei1McXB2VlhEYl9zR1luM21qUUxwdXUyQ1FMZXdZdVpvVFdPSVhQSDNGTSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
    "recipients": [{
            "encrypted_key": "G-UFZ1ebuhlWZTrMj214YcEvHl6hyfsFtWv4hj-NPNi9gpi99rRs3Q",
            "header": {
                "kid": "did:example:bob#key-p256-1"
            }
        },{
            "encrypted_key": "gVdbFdXAxEgrtj9Uw2xiEucQukpiAOA3Jp7Ecmb6L7G5c3IIcAAHgQ",
            "header": {
                "kid": "did:example:bob#key-p256-2"
            }
        }],
    "tag": "t8ioLvZhsCp7A93jvdf3wA",
    "iv": "JrIpD5q5ifMq6PT06pYh6QhCQ6LgnGpF"
}
"#;