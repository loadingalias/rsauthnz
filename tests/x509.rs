//! The X.509 certificates of TLS identities: the composite certificates of the LAMPS draft and the certificates of
//! OpenSSL 3.5.9 rebuild byte for byte, each signature verifies only with the key of its issuer, one serial of an issuer
//! gives one certificate, the profile refuses a root key of a TLS identity and a mix of classical and post-quantum
//! keys, and malformed DER refuses before allocation past the declared bound.

#[path = "counting/mod.rs"]
mod counting;

use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;

use counting::allocations;
use rsauthnz::cbor::Value;
use rsauthnz::crypto::Algorithm;
use rsauthnz::id::{Authority, Human, Id, Principal};
use rsauthnz::limits::{Limits, SignatureBudget};
use rsauthnz::store::driver::{Answer, Driver, Plan};
use rsauthnz::store::{Profile, Store as _};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{Audit, OperationId, Outcome, Proposal};
use rsauthnz::x509::{
    AltName, Attribute, CERTIFICATE_BYTES_MAX, Certificate, Draft, Error, Fields, PublicKey, Purpose, Serial, Usage,
    Validity,
};
use rsauthnz_conformance::memory::{Memory, Schedule};
use rsauthnz_conformance::suite;
use rscodec::base64::Profile::Standard;
use rscodec::json::{self, Profile::Rfc8259, Slot};

const ROOT: &[u8] = include_bytes!("x509/slh-dsa-root.der");
const ISSUER: &[u8] = include_bytes!("x509/ml-dsa-65-issuer.der");
const LEAF: &[u8] = include_bytes!("x509/ml-dsa-65-leaf.der");
const ED25519_LEAF: &[u8] = include_bytes!("x509/ed25519-leaf.der");
const ES256_LEAF: &[u8] = include_bytes!("x509/es256-leaf.der");
const VECTORS: &str = include_str!("composite-sigs/vectors.json");

/// The validity of the OpenSSL fixtures: 2026-11-21 to 2036-11-21, at midnight UTC.
const FIXTURES: Validity = Validity {
    not_before: Duration::from_secs(1_795_219_200),
    not_after: Duration::from_secs(2_110_838_400),
};

/// The names of the OpenSSL fixtures.
const ROOT_NAME: [(Attribute, &str); 3] = [
    (Attribute::Organization, "rsauthnz"),
    (Attribute::OrganizationalUnit, "fixtures"),
    (Attribute::CommonName, "SLH-DSA root"),
];
const ISSUER_NAME: [(Attribute, &str); 3] = [
    (Attribute::Organization, "rsauthnz"),
    (Attribute::OrganizationalUnit, "fixtures"),
    (Attribute::CommonName, "ML-DSA-65 issuer"),
];
const LEAF_NAME: [(Attribute, &str); 2] = [(Attribute::Organization, "rsauthnz"), (Attribute::CommonName, "build")];

/// The usage of the leaf fixtures.
const IDENTITY: Usage<'static> = Usage::Identity {
    names: &[
        AltName::Dns("build.app.example"),
        AltName::Uri("https://app.example/workload/build"),
    ],
    purposes: &[Purpose::Server, Purpose::Client],
};

fn authority() -> Id<Authority> {
    Id::new("acme", "auth").expect("an identifier")
}

fn at() -> Reading {
    Reading::new(
        Duration::from_secs(1_800_000_000),
        Some(Duration::from_secs(1)),
        ReadingSource::Caller,
    )
}

/// The output of `future`. The futures of the memory binding are ready at their first poll.
fn ready<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the memory binding does no I/O"),
    }
}

/// The memory binding and the commit driver on it.
struct Node {
    memory: Memory,
    driver: Driver,
}

impl Node {
    fn new() -> Self {
        let memory = Memory::new(Schedule::None);
        let driver = Driver::new(
            Profile::new(memory.declaration()).expect("a profile"),
            Limits::default(),
        )
        .expect("a driver");
        let mut node = Self { memory, driver };
        node.driver.start(at());
        node.run();
        node
    }

    fn run(&mut self) {
        while let Some(effect) = self.driver.effect() {
            let output = ready(suite::execute(&mut self.memory, effect));
            self.driver.give(output).expect("the driver takes the output");
        }
    }

    /// The proposal of the issue `name` of the certificate of `draft` with the signature `signature`.
    fn propose(name: &str, draft: Draft, signature: &[u8]) -> Result<Proposal, Error> {
        let audit = Audit {
            actor: Principal::Human(Id::<Human>::new("acme", "admin").expect("an identifier")),
            action: Id::new("acme", "certificate.issue").expect("an identifier"),
            time: at(),
        };
        let operation = OperationId::new(name.as_bytes()).expect("an operation identity");
        let mut proposal = Proposal::new(operation, audit, &Value::Text(name), Limits::default()).expect("a proposal");
        draft.record(&mut proposal).expect("the issuance record");
        let prepared = draft.finish(signature, &mut SignatureBudget::new(&Limits::default()))?;
        proposal.prepare(prepared).expect("the certificate");
        Ok(proposal)
    }

    fn commit(&mut self, proposal: Proposal) -> Outcome {
        let ticket = self.driver.submit(proposal, Plan::default()).expect("a submission");
        self.run();
        match self.driver.take(ticket) {
            Some(Answer::Outcome(outcome)) => outcome,
            answer => panic!("the commit gave {answer:?}"),
        }
    }

    /// The certificate of the accepted issue of `draft` with `signature`.
    fn issue(&mut self, name: &str, draft: Draft, signature: &[u8]) -> Vec<u8> {
        let proposal = Self::propose(name, draft, signature).expect("a signature of the issuer");
        let Outcome::Accepted(receipt) = self.commit(proposal) else {
            panic!("the issue does not commit");
        };
        receipt.artifact().expect("the certificate").to_vec()
    }
}

/// The three elements of the DER certificate `der` (the `TBSCertificate`, the signature algorithm, and the signature
/// bit string), each with its header, read with no code of the crate. Each length of the fixtures has at most two
/// bytes.
fn elements(der: &[u8]) -> [&[u8]; 3] {
    let header = |bytes: &[u8]| match bytes[1] {
        len @ 0..=0x7f => (2, usize::from(len)),
        0x81 => (3, usize::from(bytes[2])),
        0x82 => (4, usize::from(u16::from_be_bytes([bytes[2], bytes[3]]))),
        other => panic!("a length form {other:#x}"),
    };
    let (start, len) = header(der);
    assert_eq!(start + len, der.len());
    let mut rest = &der[start..];
    [(); 3].map(|()| {
        let (head, len) = header(rest);
        let (element, tail) = rest.split_at(head + len);
        rest = tail;
        element
    })
}

/// The signature of the DER certificate `der`: its bit string after the head and the byte of unused bits.
fn signature(der: &[u8]) -> &[u8] {
    let bits = elements(der)[2];
    let head = match bits[1] {
        0..=0x7f => 2,
        0x81 => 3,
        _ => 4,
    };
    assert_eq!(bits[head], 0, "no unused bits");
    &bits[head + 1..]
}

/// Rebuilds `der`, a certificate with `fields` that `issuer` signed, from its fields and its signature.
fn rebuild(node: &mut Node, name: &str, der: &[u8], fields: &Fields<'_>, issuer: &PublicKey) {
    let draft = Draft::new(fields, issuer, &authority()).expect("a draft");
    assert_eq!(draft.to_be_signed(), elements(der)[0], "{name}: the TBSCertificate");
    assert_eq!(node.issue(name, draft, signature(der)), der, "{name}: the certificate");
}

/// The case `id` of the composite vectors: its public key and its certificate.
fn vector(id: &str) -> (Vec<u8>, Vec<u8>) {
    let limits = json::Limits {
        input_bytes_max: 64 * 1024,
        depth_max: 3,
        string_bytes_max: 8 * 1024,
        members_max: 8,
        elements_max: 2,
        number_digits_max: 1,
    };
    let base64 = |text: &str| {
        let mut out = vec![0; Standard.decoded_len(text.as_bytes()).expect("base64")];
        Standard.decode(text.as_bytes(), &mut out).expect("base64");
        out
    };
    let mut scratch = [Slot::EMPTY; 32];
    json::read(VECTORS.as_bytes(), &limits, Rfc8259, &mut scratch, |reader| {
        let mut found = None;
        let mut members = reader.value().members()?;
        while let Some((name, value)) = members.next()? {
            if name != "tests" {
                continue;
            }
            let mut tests = value.elements()?;
            while let Some(test) = tests.next()? {
                let (mut tc, mut pk, mut x5c) = (None, None, None);
                let mut fields = test.members()?;
                while let Some((name, value)) = fields.next()? {
                    let slot = if name == "tcId" {
                        &mut tc
                    } else if name == "pk" {
                        &mut pk
                    } else if name == "x5c" {
                        &mut x5c
                    } else {
                        continue;
                    };
                    *slot = Some(value.str()?.borrowed().expect("no escape").to_owned());
                }
                if tc.as_deref() == Some(id) {
                    found = Some((base64(&pk.expect("pk")), base64(&x5c.expect("x5c"))));
                }
            }
        }
        Ok(found.expect("the case"))
    })
    .expect("the vectors")
}

#[test]
fn the_composite_certificates_of_the_lamps_draft_rebuild_byte_for_byte() {
    let mut node = Node::new();
    let cases = [
        (
            "id-MLDSA65-Ed25519-SHA512",
            Algorithm::MlDsa65Ed25519,
            "66a45be6f5a3c4915346a9408e5cfe0f729e722c",
        ),
        (
            "id-MLDSA65-ECDSA-P256-SHA512",
            Algorithm::MlDsa65EcdsaP256,
            "5b43282ced27a7bfc2874f667c3231026f701f70",
        ),
    ];
    for (id, algorithm, serial) in cases {
        let (public, der) = vector(id);
        let key = PublicKey::new(algorithm, &public).expect("the key of the case");
        let name = [
            (Attribute::Organization, "IETF"),
            (Attribute::OrganizationalUnit, "LAMPS"),
            (Attribute::CommonName, id),
        ];
        let serial: Vec<u8> = serial
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(str::from_utf8(pair).expect("ASCII"), 16).expect("hexadecimal"))
            .collect();
        let fields = Fields {
            serial: Serial::from_bytes(&serial).expect("a serial"),
            issuer: &name,
            subject: &name,
            // 2026-01-06T11:08:02Z to 2036-01-07T11:08:02Z.
            validity: Validity {
                not_before: Duration::from_secs(1_767_697_682),
                not_after: Duration::from_secs(2_083_316_882),
            },
            key: &key,
            usage: Usage::Identity {
                names: &[],
                purposes: &[],
            },
        };
        rebuild(&mut node, id, &der, &fields, &key);

        // The parse reads the same fields, and the certificate verifies with its own key.
        let certificate = Certificate::parse(&der).expect("the certificate");
        assert_eq!(
            (certificate.algorithm(), certificate.key(), certificate.serial()),
            (algorithm, &key, &fields.serial)
        );
        assert_eq!((certificate.subject(), certificate.issuer()), (&name[..], &name[..]));
        assert_eq!(
            (certificate.validity(), certificate.usage()),
            (fields.validity, fields.usage)
        );
        certificate
            .verify(&key, &mut SignatureBudget::new(&Limits::default()))
            .expect("the signature");
    }
}

#[test]
fn the_certificates_of_openssl_rebuild_byte_for_byte_and_verify_along_their_chain() {
    let mut node = Node::new();
    let root = Certificate::parse(ROOT).expect("the root");
    let issuer = Certificate::parse(ISSUER).expect("the issuer");
    let leaf = Certificate::parse(LEAF).expect("the leaf");
    let ed25519 = Certificate::parse(ED25519_LEAF).expect("the Ed25519 leaf");
    let es256 = Certificate::parse(ES256_LEAF).expect("the ES256 leaf");
    let serial = |hex: u128| Serial::from_bytes(&hex.to_be_bytes()).expect("a serial");
    let cases = [
        (
            "root",
            ROOT,
            Fields {
                serial: serial(0x4a1b_2c3d_4e5f_6071_8293_a4b5_c6d7_e8f9),
                issuer: &ROOT_NAME,
                subject: &ROOT_NAME,
                validity: FIXTURES,
                key: root.key(),
                usage: Usage::Issuer { path_length: Some(1) },
            },
            root.key(),
            Algorithm::SlhDsaSha2_128s,
        ),
        (
            "issuer",
            ISSUER,
            Fields {
                serial: serial(0x5b2c_3d4e_5f60_7182_93a4_b5c6_d7e8_f90a),
                issuer: &ROOT_NAME,
                subject: &ISSUER_NAME,
                validity: FIXTURES,
                key: issuer.key(),
                usage: Usage::Issuer { path_length: Some(0) },
            },
            root.key(),
            Algorithm::MlDsa65,
        ),
        (
            "leaf",
            LEAF,
            Fields {
                serial: serial(0x6c3d_4e5f_6071_8293_a4b5_c6d7_e8f9_0a1b),
                issuer: &ISSUER_NAME,
                subject: &LEAF_NAME,
                validity: FIXTURES,
                key: leaf.key(),
                usage: IDENTITY,
            },
            issuer.key(),
            Algorithm::MlDsa65,
        ),
        (
            "ed25519",
            ED25519_LEAF,
            Fields {
                serial: serial(0x7d4e_5f60_7182_93a4_b5c6_d7e8_f90a_1b2c),
                issuer: &LEAF_NAME,
                subject: &LEAF_NAME,
                validity: FIXTURES,
                key: ed25519.key(),
                usage: IDENTITY,
            },
            ed25519.key(),
            Algorithm::Ed25519,
        ),
        (
            "es256",
            ES256_LEAF,
            Fields {
                serial: serial(0x0e5f_6071_8293_a4b5_c6d7_e8f9_0a1b_2c3d),
                issuer: &LEAF_NAME,
                subject: &LEAF_NAME,
                validity: FIXTURES,
                key: es256.key(),
                usage: IDENTITY,
            },
            es256.key(),
            Algorithm::Es256,
        ),
    ];
    for (name, der, fields, signer, key_algorithm) in &cases {
        assert_eq!(fields.key.algorithm(), *key_algorithm, "{name}");
        rebuild(&mut node, name, der, fields, signer);
        let certificate = Certificate::parse(der).expect("the certificate");
        assert_eq!(
            (certificate.subject(), certificate.usage()),
            (fields.subject, fields.usage),
            "{name}"
        );
        certificate
            .verify(signer, &mut SignatureBudget::new(&Limits::default()))
            .unwrap_or_else(|error| panic!("{name}: {error}"));
    }
}

#[test]
fn a_certificate_verifies_only_with_the_key_of_its_issuer() {
    let budget = || SignatureBudget::new(&Limits::default());
    let root = Certificate::parse(ROOT).expect("the root");
    let issuer = Certificate::parse(ISSUER).expect("the issuer");
    let leaf = Certificate::parse(LEAF).expect("the leaf");
    // The control: the issuer key verifies the leaf.
    leaf.verify(issuer.key(), &mut budget()).expect("the signature");
    // The key of the leaf has the algorithm of the signature, and it is not the key of the issuer.
    assert_eq!(leaf.verify(leaf.key(), &mut budget()), Err(Error::Signature));
    // The root has another algorithm: it refuses before any signature work.
    let mut spent = budget();
    assert_eq!(leaf.verify(root.key(), &mut spent), Err(Error::Signature));
    assert_eq!(spent.remaining(), budget().remaining());
    // A changed byte of the common name of the leaf: the parse reads it, and its signature refuses.
    let mut changed = LEAF.to_vec();
    let at = changed
        .windows(5)
        .position(|window| window == b"build")
        .expect("the common name");
    changed[at] = b'B';
    let changed = Certificate::parse(&changed).expect("a certificate");
    assert_eq!(changed.subject()[1], (Attribute::CommonName, "Build"));
    assert_eq!(changed.verify(issuer.key(), &mut budget()), Err(Error::Signature));
}

/// The issuance record of a serial is absent before its commit, so a second certificate with the serial of an issuer
/// conflicts. A signature of another key gives no certificate.
#[test]
fn one_serial_of_an_issuer_gives_one_certificate() {
    let mut node = Node::new();
    let ed25519 = Certificate::parse(ED25519_LEAF).expect("the Ed25519 leaf");
    let fields = Fields {
        serial: *ed25519.serial(),
        issuer: &LEAF_NAME,
        subject: &LEAF_NAME,
        validity: FIXTURES,
        key: ed25519.key(),
        usage: IDENTITY,
    };
    let draft = || Draft::new(&fields, ed25519.key(), &authority()).expect("a draft");
    let wrong = signature(ES256_LEAF);
    assert_eq!(Node::propose("wrong", draft(), wrong).err(), Some(Error::Signature));
    let first = Node::propose("first", draft(), signature(ED25519_LEAF)).expect("a proposal");
    let second = Node::propose("second", draft(), signature(ED25519_LEAF)).expect("a proposal");
    assert!(matches!(node.commit(first), Outcome::Accepted(_)));
    assert!(matches!(node.commit(second), Outcome::Conflict));
}

/// A trust root signs issuer keys, not TLS identities, and a classical key never chains with a post-quantum key.
#[test]
fn a_draft_refuses_a_root_key_of_a_tls_identity_and_a_mix_of_classical_and_post_quantum_keys() {
    let root = Certificate::parse(ROOT).expect("the root");
    let issuer = Certificate::parse(ISSUER).expect("the issuer");
    let ed25519 = Certificate::parse(ED25519_LEAF).expect("the Ed25519 leaf");
    let fields = |key, usage| Fields {
        serial: *root.serial(),
        issuer: &ROOT_NAME,
        subject: &LEAF_NAME,
        validity: FIXTURES,
        key,
        usage,
    };
    let draft = |fields: &Fields<'_>, signer| Draft::new(fields, signer, &authority()).err();
    let issuers = Usage::Issuer { path_length: None };
    let cases = [
        (
            "the root signs a TLS identity",
            fields(issuer.key(), IDENTITY),
            root.key(),
        ),
        (
            "a TLS identity holds a root key",
            fields(root.key(), IDENTITY),
            issuer.key(),
        ),
        (
            "a post-quantum issuer signs a classical key",
            fields(ed25519.key(), IDENTITY),
            issuer.key(),
        ),
        (
            "a classical issuer signs a post-quantum key",
            fields(issuer.key(), issuers),
            ed25519.key(),
        ),
    ];
    for (name, fields, signer) in &cases {
        assert_eq!(draft(fields, signer), Some(Error::Profile), "{name}");
    }
    // The controls: the root signs an issuer key, and the issuer signs a TLS identity.
    assert_eq!(draft(&fields(issuer.key(), issuers), root.key()), None);
    assert_eq!(draft(&fields(issuer.key(), IDENTITY), issuer.key()), None);
}

#[test]
fn malformed_der_refuses_before_allocation_past_the_declared_bound() {
    // More bytes than the bound refuse before any read.
    let long = vec![0x30; CERTIFICATE_BYTES_MAX + 1];
    assert_eq!(allocations(|| Certificate::parse(&long).err()), (Some(Error::Bytes), 0));
    // A length past the input, a length that is not in its shortest form, and a length of three bytes refuse, and
    // the reader allocates nothing.
    let cases: [&[u8]; 4] = [
        &[0x30, 0x82, 0xff, 0xff, 0x30, 0x00],
        &[0x30, 0x81, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00],
        &[0x30, 0x83, 0x00, 0x00, 0x04, 0x30, 0x02, 0x05, 0x00],
        &[0x30, 0x84, 0x7f, 0xff, 0xff, 0xff],
    ];
    for der in cases {
        assert_eq!(
            allocations(|| Certificate::parse(der).err()),
            (Some(Error::Malformed), 0),
            "{der:02x?}"
        );
    }
    // A TBSCertificate that declares more bytes than the certificate holds refuses with no allocation.
    let mut inner = LEAF.to_vec();
    inner[6] = 0x7f;
    assert_eq!(
        allocations(|| Certificate::parse(&inner).err()),
        (Some(Error::Malformed), 0)
    );
    // Each prefix and each one-byte extension of each fixture refuses, and no input panics.
    for der in [ROOT, ISSUER, LEAF, ED25519_LEAF, ES256_LEAF] {
        for len in 0..der.len() {
            assert!(Certificate::parse(&der[..len]).is_err(), "a prefix of {len} bytes");
        }
        let longer = [der, &[0]].concat();
        assert_eq!(Certificate::parse(&longer).err(), Some(Error::Malformed));
    }
}
