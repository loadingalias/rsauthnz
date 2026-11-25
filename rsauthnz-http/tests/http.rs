//! The contracts of the HTTP binding: each state change comes from a page of the site, each cookie is a `__Host-`
//! cookie with its attributes, and each error response holds only its recovery.

use core::time::Duration;

use http::header::{HeaderMap, HeaderValue};
use http::{Request, StatusCode, Version};
use rsauthnz::id::Id;
use rsauthnz::limits::Limits;
use rsauthnz::passkey::RelyingParty;
use rsauthnz::session::Identifier;
use rsauthnz::transition::Recovery;
use rsauthnz_http::{
    CookieName, Error, Problem, RELATED_ORIGINS, Refusal, SameSite, Site, browser_module, json, problem, redirect,
    related_origins,
};

const ORIGIN: &str = "https://app.example";
const SESSION: CookieName = CookieName::new("session").expect("a token");

/// A case of the cookie read: the `cookie` fields of a request, and the value that the read finds.
type Found<'a> = (&'a [&'a [u8]], Option<&'a [u8]>);

/// A case of the JSON check: the `Origin`, the `Content-Type`, the body, and the result.
type Json<'a> = (&'a str, Option<&'a str>, &'a [u8], Result<&'a [u8], Refusal>);

/// A `POST` of `version` with the `Origin` and the `Sec-Fetch-Site` that it names.
fn change(version: Version, origin: Option<&str>, fetch_site: Option<&str>) -> Request<Vec<u8>> {
    let mut request = Request::post("/change").version(version);
    if let Some(origin) = origin {
        request = request.header("origin", origin);
    }
    if let Some(fetch_site) = fetch_site {
        request = request.header("sec-fetch-site", fetch_site);
    }
    request.body(Vec::new()).expect("a request")
}

#[test]
fn a_state_change_needs_the_origin_of_the_site_and_same_origin_fetch_metadata_in_each_http_version() {
    let site = Site::new(ORIGIN).unwrap();
    let cases = [
        (Some(ORIGIN), Some("same-origin"), Ok(())),
        (
            Some("https://attacker.example"),
            Some("same-origin"),
            Err(Refusal::Origin),
        ),
        // A sibling subdomain is the same site, not the same origin.
        (
            Some("https://other.app.example"),
            Some("same-site"),
            Err(Refusal::Origin),
        ),
        (Some("http://app.example"), Some("same-origin"), Err(Refusal::Origin)),
        // A sandboxed frame sends `null`.
        (Some("null"), Some("same-origin"), Err(Refusal::Origin)),
        (None, Some("same-origin"), Err(Refusal::Origin)),
        // No CSRF proof: each supported browser sends `Sec-Fetch-Site`.
        (Some(ORIGIN), None, Err(Refusal::FetchSite)),
        (Some(ORIGIN), Some("same-site"), Err(Refusal::FetchSite)),
        (Some(ORIGIN), Some("cross-site"), Err(Refusal::FetchSite)),
        (Some(ORIGIN), Some("none"), Err(Refusal::FetchSite)),
    ];
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        for (origin, fetch_site, expected) in cases {
            let request = change(version, origin, fetch_site);
            assert_eq!(
                site.check_change(&request),
                expected,
                "{version:?} {origin:?} {fetch_site:?}"
            );
        }
        let mut twice = change(version, Some(ORIGIN), Some("same-origin"));
        twice
            .headers_mut()
            .append("origin", HeaderValue::from_static("https://attacker.example"));
        assert_eq!(site.check_change(&twice), Err(Refusal::Origin), "{version:?}");
        // A link of another site can send a `GET` with the cookies of the site.
        let mut get = change(version, Some(ORIGIN), Some("same-origin"));
        *get.method_mut() = http::Method::GET;
        assert_eq!(site.check_change(&get), Err(Refusal::Method), "{version:?}");
    }
}

#[test]
fn the_origin_of_a_site_compares_in_the_form_that_a_browser_sends() {
    for (configured, sent) in [
        ("https://app.example", "https://app.example"),
        ("HTTPS://App.Example:443/", "https://app.example"),
        ("https://app.example:8443", "https://app.example:8443"),
        ("http://localhost:3000", "http://localhost:3000"),
        ("http://localhost:80", "http://localhost"),
    ] {
        let site = Site::new(configured).unwrap();
        let request = change(Version::HTTP_11, Some(sent), Some("same-origin"));
        assert_eq!(site.check_change(&request), Ok(()), "{configured}");
    }
    let site = Site::new("https://app.example:8443").unwrap();
    let request = change(Version::HTTP_11, Some(ORIGIN), Some("same-origin"));
    assert_eq!(site.check_change(&request), Err(Refusal::Origin));
}

#[test]
fn a_site_refuses_an_origin_that_is_not_https_and_a_domain_or_http_localhost() {
    for origin in [
        "http://app.example",
        "http://localhost.attacker.example",
        "ftp://app.example",
        "app.example",
        "https://",
        "https://app.example/app",
        "https://app.example?next=1",
        "https://app.example#top",
        "https://user@app.example",
        "https://app.example:",
        "https://app.example:0",
        "https://app.example:+443",
        "https://app.example:65536",
        "https://127.0.0.1",
        "https://[::1]",
        "https://-app.example",
        "https://app..example",
        "https://app.example.",
        "https://app_name.example",
    ] {
        assert_eq!(Site::new(origin).err(), Some(Error::Origin), "{origin}");
    }
}

#[test]
fn each_cookie_is_host_prefixed_secure_http_only_and_has_the_same_site_of_its_site() {
    let lax = Site::new(ORIGIN).unwrap();
    let strict = Site::new(ORIGIN).unwrap().same_site(SameSite::Strict);
    let mut headers = HeaderMap::new();
    lax.set_cookie(&mut headers, SESSION, b"dmFsdWU", Duration::from_secs(600))
        .unwrap();
    strict
        .set_cookie(&mut headers, SESSION, b"dmFsdWU", Duration::from_millis(1_500))
        .unwrap();
    lax.clear_cookie(&mut headers, SESSION);
    let fields: Vec<_> = headers
        .get_all("set-cookie")
        .iter()
        .map(|field| field.to_str().unwrap())
        .collect();
    assert_eq!(
        fields,
        [
            "__Host-session=dmFsdWU; Path=/; Max-Age=600; Secure; HttpOnly; SameSite=Lax",
            "__Host-session=dmFsdWU; Path=/; Max-Age=1; Secure; HttpOnly; SameSite=Strict",
            "__Host-session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax",
        ]
    );
    // No shared cache keeps a response that sets a cookie.
    assert_eq!(headers["cache-control"], "no-store");
}

#[test]
fn a_cookie_name_or_value_that_would_change_the_field_refuses() {
    let site = Site::new(ORIGIN).unwrap();
    let mut headers = HeaderMap::new();
    for value in [
        &b"v; Domain=attacker.example"[..],
        b"v\r\nset-cookie: x=y",
        b"v,w",
        b"\"v\"",
        b"v\\",
        b"v w",
        "v\u{e9}".as_bytes(),
    ] {
        let result = site.set_cookie(&mut headers, SESSION, value, Duration::from_secs(600));
        assert_eq!(result, Err(Error::CookieValue), "{value:?}");
    }
    assert!(headers.is_empty());
    for name in ["", "a b", "a;b", "a=b", "a\u{e9}"] {
        assert_eq!(CookieName::new(name), None, "{name:?}");
    }
}

#[test]
fn the_debug_output_of_a_response_does_not_show_a_cookie_value() {
    let mut response = json(Vec::new());
    let site = Site::new(ORIGIN).unwrap();
    site.set_cookie(
        response.headers_mut(),
        SESSION,
        b"c2VjcmV0LXNlc3Npb24",
        Duration::from_secs(600),
    )
    .unwrap();
    let debug = format!("{response:?}");
    // The positive control: the output shows the other fields.
    assert!(debug.contains("no-store"), "{debug}");
    assert!(!debug.contains("c2VjcmV0LXNlc3Npb24"), "{debug}");
}

/// The cookie fields `fields`, each as its bytes.
fn cookies(fields: &[&[u8]]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for field in fields {
        headers.append("cookie", HeaderValue::from_bytes(field).expect("a field value"));
    }
    headers
}

#[test]
fn a_cookie_is_found_in_each_cookie_field_and_only_with_its_prefix() {
    let found: [Found<'_>; 6] = [
        // HTTP/2 and HTTP/3 can split the cookies into several fields.
        (&[b"theme=dark", b"__Host-session=dmFsdWU; lang=en"], Some(b"dmFsdWU")),
        (&[b"theme=dark;__Host-session=dmFsdWU"], Some(b"dmFsdWU")),
        // A cookie of the application with bytes that are not a cookie value does not stop the read.
        (&[b"x=\xff\xfe; __Host-session=dmFsdWU"], Some(b"dmFsdWU")),
        // Another host can set each of these, so none is the cookie of the site.
        (
            &[b"session=dmFsdWU; __Secure-session=dmFsdWU; __host-session=dmFsdWU"],
            None,
        ),
        (&[b"theme=dark"], None),
        (&[], None),
    ];
    for (fields, expected) in found {
        assert_eq!(SESSION.find(&cookies(fields)), Ok(expected), "{fields:?}");
    }
}

#[test]
fn a_cookie_that_is_in_the_request_twice_or_not_valid_refuses() {
    for fields in [
        &[&b"__Host-session=dmFsdWU"[..], b"__Host-session=b3RoZXI"][..],
        &[b"__Host-session=dmFsdWU; __Host-session=b3RoZXI"],
        &[b"__Host-session=dmFs dWU"],
        &[b"__Host-session=\"dmFsdWU\""],
    ] {
        assert_eq!(SESSION.find(&cookies(fields)), Err(Refusal::Cookie), "{fields:?}");
    }
}

#[test]
fn a_session_cookie_round_trips_139_base64url_characters_and_refuses_an_earlier_cookie() {
    let site = Site::new(ORIGIN).unwrap();
    // The last character carries four identifier bits and two zero bits.
    let mut text: Vec<u8> = (0..139).map(|at| b"AZaz09-_"[at % 8]).collect();
    *text.last_mut().unwrap() = b'8';
    let identifier = Identifier::parse(&text).unwrap();
    let mut headers = HeaderMap::new();
    site.set_session(&mut headers, SESSION, &identifier, Duration::from_secs(600))
        .unwrap();
    let field = headers["set-cookie"].to_str().unwrap();
    let value = field
        .strip_prefix("__Host-session=")
        .and_then(|rest| rest.strip_suffix("; Path=/; Max-Age=600; Secure; HttpOnly; SameSite=Lax"))
        .unwrap();
    // An opaque value: base64url of the identifier, and no signed claim.
    assert_eq!(value.as_bytes(), text);
    let request = cookies(&[format!("__Host-session={value}").as_bytes()]);
    let read = SESSION.session(&request).unwrap().unwrap();
    assert_eq!(read.encode().unwrap().as_bytes()[..], text[..]);
    // A value that is not an identifier refuses: too short, a character of standard base64, or bits after the bytes.
    let mut standard = text.clone();
    standard[3] = b'+';
    let mut trailing = text.clone();
    *trailing.last_mut().unwrap() = b'9';
    for value in [&text[..43], &[b'A'; 86], &standard[..], &trailing[..]] {
        let request = cookies(&[&[b"__Host-session=", value].concat()]);
        assert_eq!(SESSION.session(&request).err(), Some(Refusal::Cookie));
    }
    assert!(matches!(SESSION.session(&HeaderMap::new()), Ok(None)));
}

#[test]
fn the_related_origins_document_is_the_webauthn_object_of_each_related_origin() {
    let rp = RelyingParty::new(
        Id::new("acme", "auth").unwrap(),
        "app.example",
        ORIGIN,
        "Acme",
        [3; 32],
        Limits::default(),
    )
    .unwrap()
    .with_related(&["https://app.example.de", "https://shop.example:8443"])
    .unwrap();
    let response = related_origins(&rp);
    assert_eq!(RELATED_ORIGINS, "/.well-known/webauthn");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/json");
    // WebAuthn Level 3, section 5.11: an object whose `origins` member is an array of web origins.
    assert_eq!(
        response.body(),
        br#"{"origins":["https://app.example.de","https://shop.example:8443"]}"#
    );
}

#[test]
fn the_browser_module_imports_nothing_and_stays_under_8_kib() {
    let response = browser_module();
    assert_eq!(response.headers()["content-type"], "text/javascript; charset=utf-8");
    let module = str::from_utf8(response.body()).unwrap();
    assert!(module.len() <= 8 * 1024, "{} bytes", module.len());
    // The positive control: the search sees the statements of the module.
    assert!(module.lines().any(|line| line.starts_with("export ")));
    let imports = module.lines().filter(|line| {
        let line = line.trim_start();
        line.starts_with("import ") || line.contains("import(") || line.contains("require(")
    });
    assert_eq!(imports.count(), 0);
}

/// A provider can delete a passkey at `signalUnknownCredential`, so `signIn` calls it only after the recovery
/// `forget`, which the server gives only for a passkey that a removal ended. The module keeps `forget` from the body.
#[test]
fn the_sign_in_of_the_module_tells_the_provider_to_forget_only_a_removed_passkey() {
    let response = browser_module();
    let module = str::from_utf8(response.body()).unwrap();
    let (_, sign_in) = module.split_once("export async function signIn(").expect("the sign-in");
    let (sign_in, _) = sign_in.split_once("\n}\n").expect("the end of the sign-in");
    let calls: Vec<&str> = sign_in.lines().filter(|line| line.contains("signalDeleted(")).collect();
    assert_eq!(
        calls,
        [
            r#"      if (error.recovery === "forget") await signalDeleted({ rpId: publicKey.rpId, credentialId: credential.id });"#
        ]
    );
    assert!(module.contains(r#"["restart", "check", "verify", "forget"].includes(problem.recovery)"#));
}

#[test]
fn a_json_change_admits_only_json_within_its_bound() {
    let site = Site::new(ORIGIN).unwrap();
    let request = |origin: &str, content_type: Option<&str>, body: &[u8]| {
        let mut request = Request::post("/passkey/finish")
            .header("origin", origin)
            .header("sec-fetch-site", "same-origin");
        if let Some(content_type) = content_type {
            request = request.header("content-type", content_type);
        }
        request.body(body.to_vec()).unwrap()
    };
    let cases: [Json<'_>; 8] = [
        (ORIGIN, Some("application/json"), b"{}", Ok(b"{}")),
        (ORIGIN, Some("Application/JSON; charset=UTF-8"), b"{}", Ok(b"{}")),
        // A form of another site can send these types with no preflight.
        (ORIGIN, Some("text/plain"), b"{}", Err(Refusal::ContentType)),
        (
            ORIGIN,
            Some("application/x-www-form-urlencoded"),
            b"{}",
            Err(Refusal::ContentType),
        ),
        (
            ORIGIN,
            Some("application/json; charset=iso-8859-1"),
            b"{}",
            Err(Refusal::ContentType),
        ),
        (ORIGIN, None, b"{}", Err(Refusal::ContentType)),
        (ORIGIN, Some("application/json"), b"{ }", Err(Refusal::BodyBytes)),
        (
            "https://attacker.example",
            Some("application/json"),
            b"{}",
            Err(Refusal::Origin),
        ),
    ];
    for (origin, content_type, body, expected) in cases {
        let request = request(origin, content_type, body);
        assert_eq!(site.json_change(&request, 2), expected, "{content_type:?} {body:?}");
    }
}

#[test]
fn a_redirect_goes_only_to_a_path_of_the_site() {
    let response = redirect("/account?tab=keys#top").unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()["location"], "/account?tab=keys#top");
    assert_eq!(response.headers()["cache-control"], "no-store");
    // A browser reads each of these as another host, or it is no path.
    for target in [
        "//attacker.example",
        "/\\attacker.example",
        "/\t/attacker.example",
        "https://attacker.example",
        "attacker.example",
        "",
        "/a b",
        "/a\\b",
        "/\u{e9}",
    ] {
        assert_eq!(redirect(target).err(), Some(Refusal::Redirect), "{target:?}");
    }
}

#[test]
fn an_error_response_holds_only_its_recovery() {
    let site = Site::new(ORIGIN).unwrap();
    // A refused request that holds a session cookie and a challenge.
    let request = Request::post("/passkey/finish")
        .header("origin", "https://attacker.example")
        .header("sec-fetch-site", "cross-site")
        .header("cookie", "__Host-session=c2Vzc2lvbg")
        .header("content-type", "application/json")
        .body(br#"{"challenge":"Y2hhbGxlbmdl"}"#.to_vec())
        .unwrap();
    let refusal = site.json_change(&request, 1024).unwrap_err();
    let refuse: &[u8] = br#"{"recovery":"refuse"}"#;
    let cases = [
        (refusal.response(), 403, refuse),
        (Refusal::Method.response(), 403, refuse),
        (Refusal::FetchSite.response(), 403, refuse),
        (Refusal::ContentType.response(), 415, refuse),
        (Refusal::BodyBytes.response(), 413, refuse),
        (Refusal::Cookie.response(), 400, refuse),
        (Refusal::Redirect.response(), 400, refuse),
        (problem(Recovery::Restart), 409, br#"{"recovery":"restart"}"#),
        // The browser holds no operation to look up: it checks the current state. Not 503: a client can send a
        // request again after a 503, and the first attempt can have committed.
        (problem(Recovery::Lookup), 500, br#"{"recovery":"check"}"#),
        (problem(Recovery::Verify), 403, br#"{"recovery":"verify"}"#),
        // The browser module calls `signalUnknownCredential` on this body, so the provider can delete the passkey.
        (problem(Recovery::Forget), 410, br#"{"recovery":"forget"}"#),
        (problem(Recovery::Refuse), 403, refuse),
        // The host had no room, and nothing committed: the client sends the request again after the time.
        (Problem::Busy.response(&site), 503, br#"{"recovery":"restart"}"#),
    ];
    for (response, status, body) in cases {
        assert_eq!((response.status().as_u16(), response.body().as_slice()), (status, body));
        assert_eq!(response.headers()["content-type"], "application/problem+json");
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers().get("retry-after").is_some(), status == 503);
    }
    assert_eq!(Problem::Busy.response(&site).headers()["retry-after"], "1");
}
