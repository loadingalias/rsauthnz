//! The browser consents with a passkey session. The CLI uses its device code for enrollment and signs its status call.

use axum::body::Bytes;
use http::{Method, Request, Response, header};
use rsauthnz::account::{FRESH_MAX, Fresh};
use rsauthnz::cbor::{self, Value};
use rsauthnz::cli::{Call, Challenge};
use rsauthnz::credential::Serial;
use rsauthnz::custody::Custody;
use rsauthnz::id::{Human, Id};
use rsauthnz::limits::Limits;
use rsauthnz::local::{
    Holder, Offer,
    enroll::{CliId, DeviceCode, Status, UserCode},
};
use rsauthnz::store::{Kind, driver::Plan};
use rsauthnz::time::Reading;
use rsauthnz::transition::{OperationId, Outcome, Recovery};
use rsauthnz_http::{Problem, Refusal};
use rscrypto::ChaCha20Rng;

use super::{BODY_BYTES_MAX, State, fields, ready, reply};

const REFUSE: Problem = Problem::Recovery(Recovery::Refuse);
type Reply = Result<Response<Vec<u8>>, Problem>;

/// The machine routes take bounded CBOR by POST. Only the browser routes use a session.
fn input<const N: usize>(request: &Request<Bytes>) -> Result<[Value<'_>; N], Problem> {
    if request.method() != Method::POST {
        return Err(Refusal::Method.into());
    }
    let headers = request.headers();
    if headers.contains_key(header::ORIGIN)
        || headers.contains_key("sec-fetch-site")
        || headers.contains_key(header::COOKIE)
    {
        return Err(Refusal::Origin.into());
    }
    if headers.get(header::CONTENT_TYPE).map(http::HeaderValue::as_bytes) != Some(b"application/cbor") {
        return Err(Refusal::ContentType.into());
    }
    let mut limits = Limits::default();
    limits.bytes = BODY_BYTES_MAX;
    let Value::Array(values) = cbor::decode(request.body(), limits).map_err(|_| REFUSE)? else {
        return Err(REFUSE);
    };
    values.try_into().map_err(|_| REFUSE)
}

fn output(value: &Value<'_>) -> Reply {
    let body = cbor::encode(value, Limits::default()).map_err(|_| Problem::Recovery(Recovery::Lookup))?;
    Response::builder()
        .header(header::CONTENT_TYPE, "application/cbor")
        .header(header::CACHE_CONTROL, "no-store")
        .body(body)
        .map_err(|_| Problem::Recovery(Recovery::Lookup))
}

fn device(bytes: &[u8]) -> Result<DeviceCode, Problem> {
    Ok(DeviceCode::from_bytes(bytes.try_into().map_err(|_| REFUSE)?))
}

fn identity(account: &Value<'_>, serial: u64) -> Result<CliId, Problem> {
    Ok(CliId {
        account: Id::<Human>::from_cbor(account).map_err(|_| REFUSE)?,
        serial: Serial(serial),
    })
}

fn operation(random: &mut ChaCha20Rng) -> Result<OperationId, Problem> {
    let mut bytes = [0; 32];
    random.fill_bytes(&mut bytes);
    Ok(OperationId::new(&bytes)?)
}

fn sign(issuer: &super::keys::Keys, message: &[u8], random: &mut ChaCha20Rng) -> Result<Vec<u8>, Problem> {
    issuer
        .custody
        .sign(&issuer.handle, issuer.handle.algorithm(), message, random)
        .map_err(|_| REFUSE)
}

impl State {
    fn cli_access(
        &mut self,
        request: &Request<Bytes>,
        now: Reading,
    ) -> Result<(rsauthnz::session::Access, super::Account), Problem> {
        self.access(request, now).map_err(|error| match error {
            Problem::SignedOut(_) | Problem::Recovery(Recovery::Refuse) => Problem::Recovery(Recovery::Verify),
            other => other,
        })
    }

    pub(super) fn cli_request(&mut self, request: &Request<Bytes>, now: Reading) -> Reply {
        let [code] = fields(self.site.json_change(request, BODY_BYTES_MAX)?, ["code"])?;
        let code = UserCode::parse(&code)?;
        let (_, account) = self.cli_access(request, now)?;
        let shown = ready(self.cli.request(&mut self.memory, &code, now))?;
        reply(|place| {
            place.object(|out| {
                out.member("name").str(&shown.name)?;
                out.member("account").str(&account.name)?;
                out.member("accountId").str(&account.id.to_string())?;
                out.member("fingerprint").base64url(&shown.fingerprint)?;
                out.member("approved").bool(shown.approved)
            })
        })
    }

    pub(super) fn cli_approve(&mut self, request: &Request<Bytes>, now: Reading) -> Reply {
        let [code, reviewed] = fields(self.site.json_change(request, BODY_BYTES_MAX)?, ["code", "accountId"])?;
        let code = UserCode::parse(&code)?;
        let (access, account) = self.cli_access(request, now)?;
        (account.id.to_string() == reviewed).ok_or(Problem::Recovery(Recovery::Restart))?;
        let fresh = Fresh::check(&access, FRESH_MAX, now)?;
        let serial = Serial(self.driver.allocate(Kind::Credential)?);
        let proposal = ready(
            self.cli
                .approve(&mut self.memory, &fresh, &code, serial, now, &mut self.random),
        )?;
        self.commit(proposal, now)?;
        Ok(rsauthnz_http::json(b"{}".to_vec()))
    }

    pub(super) fn cli_enroll(&mut self, request: &Request<Bytes>, now: Reading) -> Reply {
        let [Value::Text(name), Value::Bytes(holder)] = input(request)? else {
            return Err(REFUSE);
        };
        let (proposal, plan, code) =
            self.cli
                .enroll(holder.try_into().map_err(|_| REFUSE)?, name, now, &mut self.random)?;
        let device = self.artifact((proposal, plan), now)?;
        output(&Value::Array(vec![Value::Text(&code.text()), Value::Bytes(&device)]))
    }

    pub(super) fn cli_poll(&mut self, request: &Request<Bytes>, now: Reading) -> Reply {
        let [Value::Text(code), Value::Bytes(secret)] = input(request)? else {
            return Err(REFUSE);
        };
        let status = ready(
            self.cli
                .poll(&mut self.memory, &UserCode::parse(code)?, &device(secret)?, now),
        )?;
        match status {
            Status::Waiting => output(&Value::Null),
            Status::Approved(id) => {
                let account = self
                    .accounts
                    .values()
                    .find(|account| account.id == id.account)
                    .ok_or(REFUSE)?;
                output(&Value::Array(vec![
                    id.account.to_cbor(),
                    Value::Unsigned(id.serial.0),
                    Value::Text(&account.name),
                ]))
            }
        }
    }

    pub(super) fn cli_finish(&mut self, request: &Request<Bytes>, now: Reading) -> Reply {
        let [Value::Text(code), Value::Bytes(secret), account] = input(request)? else {
            return Err(REFUSE);
        };
        let account = Id::from_cbor(&account).map_err(|_| REFUSE)?;
        let draft = ready(self.cli.finish(
            &mut self.memory,
            &UserCode::parse(code)?,
            &device(secret)?,
            &account,
            now,
        ))?;
        let sig = sign(&self.issuer, &draft.to_be_signed(), &mut self.random)?;
        let proposal = draft.finish(&sig, operation(&mut self.random)?)?;
        let receipt = self.commit(proposal, now)?;
        output(&Value::Bytes(
            receipt.artifact().ok_or(Problem::Recovery(Recovery::Lookup))?,
        ))
    }

    pub(super) fn cli_credential(&mut self, request: &Request<Bytes>, now: Reading) -> Reply {
        let [account, Value::Unsigned(serial), Value::Bytes(holder)] = input(request)? else {
            return Err(REFUSE);
        };
        let id = identity(&account, serial)?;
        let draft =
            ready(
                self.cli
                    .account_credential(&mut self.memory, &id, holder.try_into().map_err(|_| REFUSE)?, now),
            )?;
        let signature = sign(&self.issuer, &draft.to_be_signed(), &mut self.random)?;
        output(&Value::Bytes(&draft.finish(&signature)?))
    }

    pub(super) fn cli_challenge(&mut self, request: &Request<Bytes>, now: Reading) -> Reply {
        let [account, Value::Unsigned(serial), Value::Bytes(holder)] = input(request)? else {
            return Err(REFUSE);
        };
        let id = identity(&account, serial)?;
        let op = operation(&mut self.random)?;
        let offer = ready(self.cli.account_challenge(
            &mut self.memory,
            &id,
            holder.try_into().map_err(|_| REFUSE)?,
            now,
            &mut self.random,
            op,
        ))?;
        match offer {
            Offer::Open(challenge) => output(&Value::Bytes(&challenge.to_bytes())),
            Offer::New(proposal, plan) => output(&Value::Bytes(&self.artifact((proposal, plan), now)?)),
        }
    }

    pub(super) fn cli_status(&mut self, request: &Request<Bytes>, now: Reading) -> Reply {
        let [
            Value::Bytes(credential),
            Value::Bytes(proof),
            Value::Bytes(challenge),
            Value::Bytes(op),
        ] = input(request)?
        else {
            return Err(REFUSE);
        };
        let challenge = Challenge::from_bytes(challenge.try_into().map_err(|_| REFUSE)?);
        let call = Call::new(
            challenge,
            OperationId::new(op)?,
            &Value::Text("status"),
            Limits::default(),
        )
        .map_err(|_| REFUSE)?;
        let (proposal, admission) =
            ready(
                self.cli
                    .admit(&mut self.memory, credential, proof, &call, now, &mut self.random),
            )?;
        let receipt = self.commit((proposal, Plan::default()), now)?;
        let admitted = admission.release(&Outcome::Accepted(receipt)).ok_or(REFUSE)?;
        if admitted.holder() != Holder::Account {
            return Err(REFUSE);
        }
        output(&admitted.subject().to_cbor())
    }
}
