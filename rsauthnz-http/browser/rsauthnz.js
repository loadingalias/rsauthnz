// The browser adapter of rsauthnz: passkey ceremonies and the Signals API of WebAuthn Level 3, with no dependency.
// The browser runs each ceremony. This module only moves JSON between the server and the WebAuthn API.

/** A refusal of the server, or an outcome that the browser cannot know. `recovery` is the action of the page:
 * "restart" (start the ceremony again), "check" (load the current state, and never send the request again), "verify"
 * (sign in again with a passkey, then start the change again), or "refuse" (stop). `status` is the HTTP status, or 0 when no response arrived. */
export class Problem extends Error {
  constructor(recovery, status) {
    super(`rsauthnz: ${recovery} (${status})`);
    this.name = "Problem";
    this.recovery = recovery;
    this.status = status;
  }
}

/** The client capabilities of WebAuthn Level 3, such as `conditionalGet` and `conditionalCreate`. A browser with no
 * `getClientCapabilities` reports only `conditionalGet`, and a browser with no WebAuthn reports nothing. */
export async function capabilities() {
  const credential = globalThis.PublicKeyCredential;
  if (!credential) return {};
  if (credential.getClientCapabilities) return credential.getClientCapabilities();
  return { conditionalGet: (await credential.isConditionalMediationAvailable?.()) === true };
}

/** Signs in with a passkey, and gives the JSON of the finish response. `options` and `finish` are the paths of the
 * server. With `conditional`, the browser offers each passkey in the autofill of an input with
 * `autocomplete="username webauthn"`, and the call waits until the user picks one. It gets new options when the
 * challenge ends. Abort it with `signal` before an explicit sign-in. A browser with no conditional mediation gives
 * `null`: show the explicit sign-in. `consent(publicKey)` can stop the ceremony before the authenticator with `false`.
 * After the recovery `forget`, it calls `signalDeleted` for the passkey, then throws the `Problem`. */
export async function signIn({ options, finish, conditional = false, signal, consent }) {
  if (conditional && !(await capabilities()).conditionalGet) return null;
  for (;;) {
    const json = await post(options, {}, signal, "restart");
    const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(json);
    if (consent && !(await consent(publicKey))) return null;
    const request = { publicKey, signal };
    let ended;
    if (conditional) {
      // A conditional request has no timeout, and the challenge ends after `timeout` milliseconds.
      const end = new AbortController();
      ended = setTimeout(() => end.abort(), json.timeout || 300000);
      request.mediation = "conditional";
      request.signal = signal ? AbortSignal.any([signal, end.signal]) : end.signal;
    }
    let credential;
    try {
      credential = await navigator.credentials.get(request);
    } catch (error) {
      if (conditional && error.name === "AbortError" && !signal?.aborted) continue;
      throw error;
    } finally {
      clearTimeout(ended);
    }
    try {
      return await post(finish, credential.toJSON(), signal, "check");
    } catch (error) {
      // The server removed this passkey for good, so the provider forgets it.
      if (error.recovery === "forget") await signalDeleted({ rpId: publicKey.rpId, credentialId: credential.id });
      throw error;
    }
  }
}

/** Registers a passkey, and gives the JSON of the finish response. `body` goes to the start request, such as the
 * account of an invitation. With `conditional`, the browser can create the passkey with no prompt after the user
 * signed in another way (conditional create, an upgrade). A browser with no conditional create gives `null`.
 * `consent(publicKey)` can stop the ceremony before the authenticator with `false`. */
export async function register({ options, finish, body = {}, conditional = false, signal, consent }) {
  if (conditional && !(await capabilities()).conditionalCreate) return null;
  const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(await post(options, body, signal, "restart"));
  if (consent && !(await consent(publicKey))) return null;
  const request = { publicKey, signal };
  if (conditional) request.mediation = "conditional";
  const credential = await navigator.credentials.create(request);
  return post(finish, credential.toJSON(), signal, "check");
}

/** A JSON state change with no ceremony, such as a rename or a sign-out: a `POST` of `body` to `path`. It gives the JSON
 * of the response, or throws a `Problem`. A request with no response can have committed, so its recovery is `check`. */
export function change(path, body = {}, { signal } = {}) {
  return post(path, body, signal, "check");
}

/** After the deletion of the passkey `credentialId` (base64url): the provider removes it. Gives `false` when the
 * browser has no Signals API. */
export function signalDeleted({ rpId, credentialId }) {
  return notify("signalUnknownCredential", { rpId, credentialId });
}

/** After a change of the passkeys of the account `userId` (its user handle, base64url): the provider keeps only the
 * passkeys of `credentialIds`. Gives `false` when the browser has no Signals API. */
export function signalAccepted({ rpId, userId, credentialIds }) {
  return notify("signalAllAcceptedCredentials", { rpId, userId, allAcceptedCredentialIds: credentialIds });
}

/** After a rename of the account `userId`: the provider shows `name` and `displayName`. Gives `false` when the browser
 * has no Signals API. */
export function signalRenamed({ rpId, userId, name, displayName }) {
  return notify("signalCurrentUserDetails", { rpId, userId, name, displayName });
}

async function notify(method, details) {
  const call = globalThis.PublicKeyCredential?.[method];
  if (!call) return false;
  await call.call(PublicKeyCredential, details);
  return true;
}

// A same-origin JSON state change, which the HTTP binding checks. With no response, the recovery is `lost`: "restart"
// for a request that commits nothing, where an abort of `signal` stays an abort, and "check" for a finish, which can
// have committed also when it was aborted.
async function post(path, body, signal, lost) {
  let response;
  try {
    response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal,
    });
  } catch (error) {
    if (lost === "restart" && signal?.aborted) throw error;
    throw new Problem(lost, 0);
  }
  if (!response.ok) {
    const problem = await response.json().catch(() => ({}));
    const known = ["restart", "check", "verify", "forget"].includes(problem.recovery);
    throw new Problem(known ? problem.recovery : "refuse", response.status);
  }
  return response.json();
}
