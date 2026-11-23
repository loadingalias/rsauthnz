// The page of the web example: each action calls the server through the browser adapter of rsauthnz-http.
import { signIn, register, change, signalDeleted, signalAccepted, signalRenamed, Problem } from "/rsauthnz.js";

const $ = (id) => document.getElementById(id);
const show = (text) => { $("status").textContent = text; };

/** Runs `action`, and shows the recovery of a problem. `verify` asks for a new sign-in, which replaces the session. */
async function run(action) {
  try {
    await action();
  } catch (error) {
    if (!(error instanceof Problem)) throw error;
    show(error.recovery === "verify" ? "Sign in again to confirm this change, then try again." : `Refused: ${error.recovery}`);
  }
  await load();
}

/**
 * Shows the account of the session, or the signed-out page. Each load also gives the passkey provider the names and
 * the passkeys of the account, so a provider learns a rename or a removal at the next sign-in on its device.
 */
async function load() {
  const response = await fetch("/account");
  const signedIn = response.ok;
  $("signed-in").hidden = !signedIn;
  $("signed-out").hidden = signedIn;
  if (!signedIn) return;
  const account = await response.json();
  $("account").textContent = `${account.displayName} (${account.name})`;
  $("rename").elements.namedItem("name").value = account.name;
  $("rename").elements.namedItem("displayName").value = account.displayName;
  $("passkeys").replaceChildren(...account.passkeys.map((passkey) => {
    const item = document.createElement("li");
    item.textContent = passkey.name || "(no name)";
    const rename = document.createElement("button");
    rename.textContent = "Rename";
    rename.onclick = () => run(async () => {
      const name = prompt("New name of the passkey");
      if (name) await change("/passkeys/rename", { id: passkey.id, name });
    });
    const remove = document.createElement("button");
    remove.textContent = "Remove";
    remove.onclick = () => run(async () => {
      await change("/passkeys/remove", { id: passkey.id });
      await signalDeleted({ rpId: account.rpId, credentialId: passkey.id });
    });
    item.append(" ", rename, " ", remove);
    return item;
  }));
  $("sessions").replaceChildren(...account.sessions.map((session) => {
    const item = document.createElement("li");
    item.textContent = session.current ? "This browser " : "Another browser ";
    const end = document.createElement("button");
    end.textContent = "End";
    end.onclick = () => run(() => change("/sessions/revoke", { key: session.key }));
    item.append(end);
    return item;
  }));
  await signalRenamed(account);
  await signalAccepted({ ...account, credentialIds: account.passkeys.map((passkey) => passkey.id) });
}

const form = (id, action) => {
  $(id).onsubmit = (event) => {
    event.preventDefault();
    run(() => action(Object.fromEntries(new FormData(event.target))));
  };
};

form("sign-in", () => signIn({ options: "/sign-in/options", finish: "/sign-in/finish" }));
form("sign-up", async ({ name }) => {
  await register({ options: "/sign-up/options", finish: "/sign-up/finish", body: { name } });
  show("Your passkey is ready. Sign in with it.");
});
form("activate", async ({ name, invitation }) => {
  await register({ options: "/invitation/options", finish: `/invitation/finish/${name}`, body: { name, invitation } });
  show("The account is active. Sign in with its passkey.");
});
form("recover", async ({ name, code }) => {
  await register({ options: "/recover/options", finish: "/recover/finish", body: { name, code } });
  show("Recovered. Make a new recovery code now: the old code is spent.");
});
form("invite", async ({ name }) => {
  const { invitation } = await change("/invitations", { name });
  show(`Send this invitation to ${name}: ${invitation}`);
});
form("rename", (names) => change("/account/rename", names));
$("add").onclick = () => run(() => register({ options: "/passkeys/add/options", finish: "/passkeys/add/finish" }));
$("code").onclick = () => run(async () => {
  const { code } = await change("/recovery-code");
  show(`Your recovery code, shown once: ${code}`);
});
$("sign-out").onclick = () => run(() => change("/sign-out"));
load();
