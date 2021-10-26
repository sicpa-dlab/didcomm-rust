use std::collections::HashMap;
use std::ops::Deref;
use crate::did::{DIDDoc, VerificationMaterial, VerificationMethod};
use crate::did::resolvers::ExampleDIDResolver;
use crate::secrets::resolvers::ExampleSecretsResolver;
use crate::test_vectors::ALICE_DID_DOC;
use crate::test_vectors::BOB_DID_DOC;
use crate::test_vectors::ALICE_SECRETS;
use crate::test_vectors::BOB_SECRETS;
use crate::did::did_doc::VerificationMethodType;
use crate::jwe::parse;

#[derive(PartialEq, Eq, Hash)]
pub(crate) enum Person {
    ALICE = 1,
    BOB = 2,
    CHARLIE = 3,
}

#[derive(PartialEq, Eq)]
pub(crate) enum KeyAgreementCurveType {
    ALL = 0,
    X25519 = 1,
    P256 = 2,
}

const DID_DOCS_SPEC: HashMap<Person, (DIDDoc, ExampleSecretsResolver)> =
    [(Person::ALICE,
      (*ALICE_DID_DOC, ExampleSecretsResolver::new(ALICE_SECRETS.clone()))),
        (Person::BOB,
         (*BOB_DID_DOC, ExampleSecretsResolver::new(BOB_SECRETS.clone())))
    ]
        .iter().map(|&x| x).collect();

fn get_did_doc(person: Person) -> DIDDoc {
    let (did_doc, sr) = DID_DOCS_SPEC.get(&person);
    return did_doc;
}

fn get_secret_resolver(person: Person) -> ExampleSecretsResolver {
    let spec = DID_DOCS_SPEC.get(&person);
    return spec[1];
}

pub(crate) fn get_key_agreement_methods(person: Person, curve_type: KeyAgreementCurveType) -> Vec<&'static VerificationMethod> {
    let mut did_doc = get_did_doc(person);
    return did_doc.verification_methods.iter().filter(|&&vm| did_doc.key_agreements.contains(&vm.id) &&
        (curve_type == KeyAgreementCurveType::ALL || curve_type == map_cure_to_type(vm))).collect();
}

fn map_cure_to_type(vm: VerificationMethod) -> KeyAgreementCurveType {
    if vm.type_ == VerificationMethodType::JsonWebKey2020 &&
        vm.verification_material == VerificationMaterial::JWK {
        let jwk = parse(vm.verificationMaterial.value);
        if jwk["crv"] == "X25519" {
            return KeyAgreementCurveType::X25519;
        }
        if jwk["crv"] == "P-256" {
            return KeyAgreementCurveType::P256;
        }
    }
    panic!("Unsupported verification method type or verification material");
}
