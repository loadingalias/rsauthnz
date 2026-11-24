// Observe the public options and results of this page. The account forms use the unmodified web application.
import { capabilities, register, signIn } from "/rsauthnz.js";

const send = window.fetch.bind(window);
const byId = (id) => document.getElementById(id);
const show = (message) => { byId("provider-status").textContent = message; };

function report(event, ...values) {
  void send("/run/observation", { method: "POST", body: [event, ...values].join(" ") }).catch(() => {
    show("The observation server is unavailable.");
  });
}

const offers = new Map([
  ["/sign-up/options", "signup-offer"], ["/passkeys/add/options", "add-offer"],
  ["/invitation/options", "invite-offer"], ["/recover/options", "recover-offer"],
]);
const results = new Map([
  ["/sign-up/finish", "signup"], ["/passkeys/add/finish", "add"], ["/recover/finish", "recover"],
  ["/sign-in/finish", "signin"], ["/account", "account"], ["/sessions/revoke", "revoke"],
  ["/sessions/renew", "renew"], ["/sign-out", "signout"], ["/passkeys/remove", "remove"], ["/account/rename", "rename"],
]);

function registrationResult(event, status, text) {
  const answer = JSON.parse(text);
  const data = answer.response.authenticatorData;
  const algorithm = answer.response.publicKeyAlgorithm;
  const attachment = answer.authenticatorAttachment ?? "unknown";
  const values = [status, Number.isInteger(algorithm) ? algorithm : "missing", attachment];
  if (typeof data === "string") {
    const flags = atob(data.replaceAll("-", "+").replaceAll("_", "/")).charCodeAt(32);
    if (Number.isInteger(flags)) {
      values.push(flags & 4 ? "uv" : "no-uv", flags & 8 ? "backup-eligible" : "device-bound", flags & 16 ? "backed-up" : "not-backed-up");
    }
  }
  report(event, ...values);
}

window.fetch = async (input, init) => {
  const response = await send(input, init);
  const url = new URL(input instanceof Request ? input.url : input, location.href);
  if (url.origin !== location.origin) return response;
  const offer = offers.get(url.pathname);
  const event = url.pathname.startsWith("/invitation/finish/") ? "activate" : results.get(url.pathname);
  try {
    if (offer && !response.ok) {
      const problem = await response.clone().json();
      report(offer, response.status, problem.recovery ?? "unknown");
    } else if (offer) {
      const options = await response.clone().json();
      report(offer, ...options.pubKeyCredParams.map((item) => item.alg));
    }
    if (event) {
      if (["signup", "add", "activate", "recover"].includes(event)) {
        registrationResult(event, response.status, init.body);
      } else if (!response.ok) {
        const problem = await response.clone().json();
        report(event, response.status, problem.recovery ?? "unknown");
      } else {
        report(event, response.status);
      }
    }
  } catch {
    if (event || offer) report(event ?? offer, "unknown");
  }
  return response;
};

for (const [target, method, event] of [
  [navigator.credentials, "create", "provider-create"],
  [navigator.credentials, "get", "provider-get"],
  [globalThis.PublicKeyCredential, "signalUnknownCredential", "unknown-credential"],
  [globalThis.PublicKeyCredential, "signalAllAcceptedCredentials", "accepted-credentials"],
  [globalThis.PublicKeyCredential, "signalCurrentUserDetails", "user-details"],
]) {
  const original = target?.[method];
  if (typeof original !== "function") {
    report(event, "unsupported");
    continue;
  }
  try {
    target[method] = async function (...args) {
      try {
        const result = await original.apply(this, args);
        report(event, "ok");
        return result;
      } catch (error) {
        const reason = { AbortError: "stopped", NotAllowedError: "not-allowed", NotSupportedError: "unsupported" };
        report(event, reason[error.name] ?? "refused");
        throw error;
      }
    };
  } catch {
    report(event, "unknown");
  }
}

const browser = navigator.userAgent.includes("Firefox/") ? "firefox" : navigator.userAgent.includes("Chrome/") ? "chrome" : "safari";
const testName = sessionStorage.getItem("rsauthnz-e8-name") ?? "e8-" + browser + "-" + crypto.randomUUID().slice(0, 8);
sessionStorage.setItem("rsauthnz-e8-name", testName);
document.querySelector("#sign-up input").value = testName;
await import("/app.js");
report("page", "ready");
const features = await capabilities();
for (const [key, event] of [["conditionalGet", "conditional-get"], ["conditionalCreate", "conditional-create"]]) {
  report(event, features[key] === true ? "yes" : features[key] === false ? "no" : "missing");
}

let pending;
const stop = byId("stop-conditional");
stop.onclick = () => pending?.abort();
for (const id of ["sign-in", "sign-up"]) byId(id).addEventListener("submit", () => pending?.abort(), true);

async function conditional(create) {
  if (pending) return;
  pending = new AbortController();
  stop.disabled = false;
  const signal = pending.signal;
  try {
    show(create ? "Waiting for conditional creation." : "Select the passkey from the name field.");
    if (!create) document.querySelector("#sign-in input").focus();
    const result = create ?
      await register({ options: "/passkeys/add/options", finish: "/passkeys/add/finish", conditional: true, signal }) :
      await signIn({ options: "/sign-in/options", finish: "/sign-in/finish", conditional: true, signal });
    report("conditional-result", result === null ? "unsupported" : "ok");
    if (result === null) show(create ? "Use Add a passkey for explicit registration." : "Use Sign in with a passkey.");
    else location.reload();
  } catch (error) {
    report("conditional-result", error.name === "AbortError" ? "stopped" : "refused");
    show(error.recovery === "verify" ? "Sign in again before adding a passkey." : "The conditional request stopped. Check the account.");
  } finally {
    pending = undefined;
    stop.disabled = true;
  }
}

byId("conditional-get").onclick = () => conditional(false);
byId("conditional-create").onclick = () => conditional(true);
byId("cancel-consent").onclick = async () => {
  pending?.abort();
  const result = await signIn({ options: "/sign-in/options", finish: "/sign-in/finish", consent: () => false });
  if (result === null) {
    report("consent", "canceled");
    show("Sign-in canceled before the provider prompt.");
  }
};
