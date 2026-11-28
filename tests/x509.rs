//! X.509 certificates: the composite certificates of the LAMPS draft and the certificates of OpenSSL 3.5.9 rebuild byte
//! for byte, each signature verifies only with the key of its issuer, one serial of an issuer gives one certificate, the
//! profile refuses a root key of a TLS identity and a mix of classical and post-quantum keys, and malformed DER refuses
//! before allocation past the declared bound. The Fulcio certificate of a real GitHub Actions release verifies along its
//! Sigstore chain at the time of its log entry, with its claims and the timestamp of its CT log, and each broken path
//! refuses with its typed error.

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
    AltName, Attribute, CERTIFICATE_BYTES_MAX, Certificate, Draft, Error, Fields, Fulcio, Name, PublicKey, Purpose,
    Serial, Timestamp, Usage, Validity,
};
use rsauthnz_conformance::memory::{Memory, Schedule};
use rsauthnz_conformance::suite;
use rscodec::base64::Profile::Standard;
use rscodec::json::{self, Profile::Rfc8259, Slot};
use rscrypto::ChaCha20Rng;
use rscrypto::auth::Ed25519SecretKey;

const ROOT: &[u8] = include_bytes!("x509/slh-dsa-root.der");
const ISSUER: &[u8] = include_bytes!("x509/ml-dsa-65-issuer.der");
const LEAF: &[u8] = include_bytes!("x509/ml-dsa-65-leaf.der");
const ED25519_LEAF: &[u8] = include_bytes!("x509/ed25519-leaf.der");
const ES256_LEAF: &[u8] = include_bytes!("x509/es256-leaf.der");
const VECTORS: &str = include_str!("composite-sigs/vectors.json");
const SIGSTORE_ROOT: &[u8] = include_bytes!("x509/sigstore-root.der");
const SIGSTORE_INTERMEDIATE: &[u8] = include_bytes!("x509/sigstore-intermediate.der");
const FULCIO_LEAF: &[u8] = include_bytes!("x509/fulcio-leaf.der");
const CT_LOG: &[u8] = include_bytes!("x509/ctfe-2022.der");

/// The validity of the Fulcio leaf, as OpenSSL 3 printed it: 2024-03-19 22:41:15 to 22:51:15 UTC.
const FULCIO_VALIDITY: Validity = Validity {
    not_before: Duration::from_secs(1_710_888_075),
    not_after: Duration::from_secs(1_710_888_675),
};

/// The `integratedTime` of the Rekor entry of the Fulcio leaf, in its bundle: 2024-03-19 22:41:16 UTC.
const LOGGED: Duration = Duration::from_secs(1_710_888_076);

/// The workflow of the release that the Fulcio leaf names.
const WORKFLOW: &str = "https://github.com/trailofbits/rfc8785.py/.github/workflows/release.yml@refs/tags/v0.1.2";

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
            &mut ChaCha20Rng::from_seed([11; 32]),
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
                usage: Usage::Issuer {
                    path_length: Some(1),
                    purposes: &[],
                },
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
                usage: Usage::Issuer {
                    path_length: Some(0),
                    purposes: &[],
                },
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

/// A trust root signs issuer keys, not TLS identities, a classical key never chains with a post-quantum key, and this
/// crate issues no ES384 certificate.
#[test]
fn a_draft_refuses_a_root_key_of_a_tls_identity_and_a_mix_of_classical_and_post_quantum_keys() {
    let root = Certificate::parse(ROOT).expect("the root");
    let issuer = Certificate::parse(ISSUER).expect("the issuer");
    let ed25519 = Certificate::parse(ED25519_LEAF).expect("the Ed25519 leaf");
    let es384 = Certificate::parse(SIGSTORE_INTERMEDIATE).expect("the Sigstore intermediate");
    let fields = |key, usage| Fields {
        serial: *root.serial(),
        issuer: &ROOT_NAME,
        subject: &LEAF_NAME,
        validity: FIXTURES,
        key,
        usage,
    };
    let draft = |fields: &Fields<'_>, signer| Draft::new(fields, signer, &authority()).err();
    let issuers = Usage::Issuer {
        path_length: None,
        purposes: &[],
    };
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
        (
            "an ES384 issuer signs a classical key",
            fields(ed25519.key(), IDENTITY),
            es384.key(),
        ),
        (
            "a classical issuer signs an ES384 key",
            fields(es384.key(), issuers),
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
    for der in [
        ROOT,
        ISSUER,
        LEAF,
        ED25519_LEAF,
        ES256_LEAF,
        SIGSTORE_ROOT,
        SIGSTORE_INTERMEDIATE,
        FULCIO_LEAF,
    ] {
        for len in 0..der.len() {
            assert!(Certificate::parse(&der[..len]).is_err(), "a prefix of {len} bytes");
        }
        let longer = [der, &[0]].concat();
        assert_eq!(Certificate::parse(&longer).err(), Some(Error::Malformed));
    }
}

/// The time of the checks of the paths of this crate: in the validity of the fixtures.
const NOW: Duration = Duration::from_secs(1_800_000_000);

/// The Sigstore root, its intermediate, and the Fulcio leaf.
fn sigstore() -> [Certificate<'static>; 3] {
    [SIGSTORE_ROOT, SIGSTORE_INTERMEDIATE, FULCIO_LEAF].map(|der| Certificate::parse(der).expect("a certificate"))
}

/// The certificate that the Ed25519 key `signer` with the name `issuer` issues, through a commit, for the Ed25519 key
/// `key` with the name `subject`.
fn ed25519_certificate(
    node: &mut Node,
    serial: u8,
    (signer, issuer): (&Ed25519SecretKey, &Name<'_>),
    (key, subject): (&Ed25519SecretKey, &Name<'_>),
    usage: Usage<'_>,
) -> Vec<u8> {
    let public = |key: &Ed25519SecretKey| {
        PublicKey::new(Algorithm::Ed25519, &key.public_key().to_bytes()).expect("an Ed25519 key")
    };
    let fields = Fields {
        serial: Serial::from_bytes(&[serial]).expect("a serial"),
        issuer,
        subject,
        validity: FIXTURES,
        key: &public(key),
        usage,
    };
    let draft = Draft::new(&fields, &public(signer), &authority()).expect("a draft");
    let signature = signer.sign(draft.to_be_signed()).to_bytes();
    node.issue(&serial.to_string(), draft, &signature)
}

#[test]
fn a_fulcio_leaf_of_a_github_actions_release_verifies_along_its_sigstore_chain_at_the_time_of_its_log_entry() {
    let [root, intermediate, leaf] = sigstore();
    let issuers = [intermediate];
    leaf.verify_path(
        &issuers,
        &root,
        LOGGED,
        Purpose::CodeSigning,
        &mut SignatureBudget::new(&Limits::default()),
    )
    .expect("the path");
    // The forms and the claims that OpenSSL 3 printed.
    assert_eq!(
        (leaf.algorithm(), leaf.key().algorithm(), leaf.validity()),
        (Algorithm::Es384, Algorithm::Es256, FULCIO_VALIDITY)
    );
    assert!(leaf.subject().is_empty());
    assert_eq!(
        leaf.usage(),
        Usage::Identity {
            names: &[AltName::Uri(WORKFLOW)],
            purposes: &[Purpose::CodeSigning],
        }
    );
    assert_eq!(
        issuers[0].usage(),
        Usage::Issuer {
            path_length: Some(0),
            purposes: &[Purpose::CodeSigning],
        }
    );
    assert_eq!(
        root.subject(),
        [
            (Attribute::Organization, "sigstore.dev"),
            (Attribute::CommonName, "sigstore")
        ]
    );
    let commit = Some("d8b4a6445f38c48b9137a8099706d9b8073146e4");
    let claims = Fulcio {
        issuer: Some("https://token.actions.githubusercontent.com"),
        build_signer_uri: Some(WORKFLOW),
        build_signer_digest: commit,
        runner_environment: Some("github-hosted"),
        source_repository_uri: Some("https://github.com/trailofbits/rfc8785.py"),
        source_repository_digest: commit,
        source_repository_ref: Some("refs/tags/v0.1.2"),
        source_repository_identifier: Some("768213997"),
        source_repository_owner_uri: Some("https://github.com/trailofbits"),
        source_repository_owner_identifier: Some("2314423"),
        build_config_uri: Some(WORKFLOW),
        build_config_digest: commit,
        build_trigger: Some("release"),
        run_invocation_uri: Some("https://github.com/trailofbits/rfc8785.py/actions/runs/8351058501/attempts/1"),
        source_repository_visibility: Some("public"),
    };
    assert_eq!(leaf.fulcio(), Some(&claims));
}

/// The validity holds from its first second to its last second.
#[test]
fn a_path_refuses_one_second_outside_the_validity_of_a_certificate() {
    let [root, intermediate, leaf] = sigstore();
    let issuers = [intermediate];
    let check = |at| {
        leaf.verify_path(
            &issuers,
            &root,
            at,
            Purpose::CodeSigning,
            &mut SignatureBudget::new(&Limits::default()),
        )
    };
    let Validity { not_before, not_after } = FULCIO_VALIDITY;
    let second = Duration::from_secs(1);
    assert_eq!(check(not_before), Ok(()));
    assert_eq!(check(not_after), Ok(()));
    assert_eq!(check(not_before.checked_sub(second).unwrap()), Err(Error::Time));
    assert_eq!(check(not_after + second), Err(Error::Time));
}

#[test]
fn a_path_refuses_a_wrong_order_another_anchor_and_a_wrong_purpose() {
    let [root, intermediate, leaf] = sigstore();
    let other = Certificate::parse(ROOT).expect("the OpenSSL root");
    let check = |issuers: &[Certificate<'static>], anchor: &Certificate<'static>, purpose| {
        leaf.verify_path(
            issuers,
            anchor,
            LOGGED,
            purpose,
            &mut SignatureBudget::new(&Limits::default()),
        )
    };
    let code = Purpose::CodeSigning;
    // The control.
    assert_eq!(check(core::slice::from_ref(&intermediate), &root, code), Ok(()));
    let cases = [
        (
            "a wrong order",
            check(core::slice::from_ref(&root), &intermediate, code),
            Error::Path,
        ),
        (
            "another anchor",
            check(core::slice::from_ref(&intermediate), &other, code),
            Error::Path,
        ),
        ("no issuer", check(&[], &root, code), Error::Path),
        (
            "more issuers than the bound",
            check(
                &[
                    intermediate.clone(),
                    root.clone(),
                    root.clone(),
                    root.clone(),
                    root.clone(),
                ],
                &root,
                code,
            ),
            Error::Path,
        ),
        (
            "a TLS server",
            check(core::slice::from_ref(&intermediate), &root, Purpose::Server),
            Error::Purpose,
        ),
    ];
    for (name, checked, error) in cases {
        assert_eq!(checked, Err(error), "{name}");
    }
}

/// An issuer bounds the issuer certificates under it with its path length, and the purposes under it with its own. A
/// TLS identity issues no certificate.
#[test]
fn a_path_refuses_an_issuer_that_is_no_issuer_certificate_a_path_past_its_length_and_a_purpose_outside_an_issuer() {
    let mut node = Node::new();
    let [root_key, middle_key, leaf_key] = [1, 2, 3].map(|seed| Ed25519SecretKey::from_bytes([seed; 32]));
    let root = (&root_key, &ROOT_NAME[..]);
    let middle = (&middle_key, &ISSUER_NAME[..]);
    let issuer = |path_length, purposes| Usage::Issuer { path_length, purposes };
    let identity = Usage::Identity {
        names: &[],
        purposes: &[Purpose::Server],
    };
    let der = [
        ed25519_certificate(&mut node, 1, root, root, issuer(Some(0), &[])),
        ed25519_certificate(&mut node, 2, root, root, issuer(Some(1), &[])),
        ed25519_certificate(&mut node, 3, root, middle, issuer(None, &[])),
        ed25519_certificate(&mut node, 4, root, middle, issuer(None, &[Purpose::Client])),
        // A TLS identity with the name and the key of the issuer.
        ed25519_certificate(&mut node, 5, root, middle, identity),
        ed25519_certificate(&mut node, 6, middle, (&leaf_key, &LEAF_NAME[..]), identity),
    ];
    let [root_of_0, root_of_1, middle, client_middle, identity_middle, leaf] = der
        .each_ref()
        .map(|der| Certificate::parse(der).expect("a certificate"));
    let check = |issuer: &Certificate<'_>, anchor: &Certificate<'_>| {
        leaf.verify_path(
            core::slice::from_ref(issuer),
            anchor,
            NOW,
            Purpose::Server,
            &mut SignatureBudget::new(&Limits::default()),
        )
    };
    // The control: the root of the path length 1 has one issuer certificate under it.
    assert_eq!(check(&middle, &root_of_1), Ok(()));
    assert_eq!(check(&middle, &root_of_0), Err(Error::Path));
    assert_eq!(check(&client_middle, &root_of_1), Err(Error::Purpose));
    assert_eq!(check(&identity_middle, &root_of_1), Err(Error::Path));
}

#[test]
fn the_timestamp_of_a_fulcio_leaf_verifies_with_the_key_of_its_ct_log() {
    let [root, intermediate, leaf] = sigstore();
    let budget = || SignatureBudget::new(&Limits::default());
    let log = PublicKey::from_spki(Algorithm::Es256, CT_LOG).expect("the key of the log");
    // The caller fixes the algorithm of the key: the input does not select it.
    assert_eq!(PublicKey::from_spki(Algorithm::Es384, CT_LOG).err(), Some(Error::Key));
    let other = Certificate::parse(ES256_LEAF).expect("the ES256 leaf").key().clone();
    // The time that OpenSSL 3 printed: 2024-03-19 22:41:15.966 UTC.
    let logged = Timestamp {
        log: 1,
        time: Duration::from_millis(1_710_888_075_966),
    };
    assert_eq!(
        leaf.timestamps(&intermediate, &[other.clone(), log.clone()], &mut budget()),
        Ok(vec![logged])
    );
    // Another log gives no timestamp, and no signature work.
    let mut spent = budget();
    assert_eq!(leaf.timestamps(&intermediate, &[other], &mut spent), Ok(vec![]));
    assert_eq!(spent.remaining(), budget().remaining());
    // The log signed the key of the issuer with the certificate: another issuer refuses.
    assert_eq!(
        leaf.timestamps(&root, core::slice::from_ref(&log), &mut budget()),
        Err(Error::Timestamp)
    );
    // A changed claim: the parse reads it, and the timestamp refuses.
    let mut changed = FULCIO_LEAF.to_vec();
    let at = changed
        .windows(13)
        .position(|window| window == b"github-hosted")
        .expect("the runner environment");
    changed[at] = b'G';
    let changed = Certificate::parse(&changed).expect("a certificate");
    assert_eq!(
        changed.timestamps(&intermediate, &[log], &mut budget()),
        Err(Error::Timestamp)
    );
    // A log key that is not ES256 refuses.
    assert_eq!(
        leaf.timestamps(&intermediate, &[intermediate.key().clone()], &mut budget()),
        Err(Error::Unsupported)
    );
}

#[test]
fn a_timestamp_list_outside_the_form_of_rfc_6962_refuses() {
    let [_, intermediate, _] = sigstore();
    let log = PublicKey::from_spki(Algorithm::Es256, CT_LOG).expect("the key of the log");
    // The list of the leaf, read with no code of the crate: after its OID, the octet string of the extension (124
    // bytes), the octet string of the list (122 bytes), and the length of the list (120 bytes).
    let oid = [0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02];
    let start = FULCIO_LEAF
        .windows(oid.len())
        .position(|window| window == oid)
        .expect("the extension")
        + oid.len();
    assert_eq!(FULCIO_LEAF[start..start + 6], [0x04, 0x7c, 0x04, 0x7a, 0x00, 0x78]);
    let list = start + 4;
    let cases = [
        ("a list one byte longer than its bytes", list + 1, Error::Malformed),
        ("a timestamp of version 2", list + 4, Error::Unsupported),
    ];
    for (name, at, error) in cases {
        let mut changed = FULCIO_LEAF.to_vec();
        changed[at] += 1;
        let changed = Certificate::parse(&changed).expect("a certificate");
        assert_eq!(
            changed.timestamps(
                &intermediate,
                core::slice::from_ref(&log),
                &mut SignatureBudget::new(&Limits::default())
            ),
            Err(error),
            "{name}"
        );
    }
}
