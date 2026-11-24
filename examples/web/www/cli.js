import { change, Problem, signIn } from "/rsauthnz.js";

const element = (id) => document.getElementById(id);
const form = element("review");
const code = element("code");
const details = element("details");
const message = element("message");
const verify = element("verify");
const approve = element("approve");
let reviewed;

async function review() {
  details.hidden = true;
  reviewed = undefined;
  const value = code.value.trim();
  const request = await change("/cli/request", { code: value });
  if (request.approved) {
    message.textContent = "Already approved. Check the approving account in your terminal.";
    return;
  }
  element("device").textContent = request.name;
  element("owner").textContent = request.account;
  element("fingerprint").textContent = request.fingerprint;
  reviewed = { code: value, accountId: request.accountId };
  details.hidden = false;
  message.textContent = "";
}

async function run(action) {
  code.disabled = true;
  form.querySelector("button").disabled = verify.disabled = approve.disabled = true;
  verify.hidden = true;
  try {
    await action();
  } catch (error) {
    details.hidden = true;
    reviewed = undefined;
    if (error instanceof Problem && error.recovery === "verify") {
      verify.hidden = false;
      message.textContent = "Sign in with a passkey to review this request.";
    } else if (error instanceof Problem && error.recovery === "check") {
      message.textContent = "The response was lost. Check your terminal or review the request again.";
    } else if (error instanceof Problem && error.recovery === "restart") {
      message.textContent = "Review the request again. If the code expired, start enrollment again in your terminal.";
    } else if (error instanceof Problem && error.recovery === "forget") {
      verify.hidden = false;
      message.textContent = "This passkey was removed. Sign in with another passkey.";
    } else if (error.name === "NotAllowedError") {
      verify.hidden = false;
      message.textContent = "Sign-in was canceled. You can try again.";
    } else {
      message.textContent = "This request is unavailable. Check the code in your terminal.";
    }
  } finally {
    code.disabled = false;
    form.querySelector("button").disabled = verify.disabled = approve.disabled = false;
  }
}

code.oninput = () => {
  reviewed = undefined;
  details.hidden = verify.hidden = true;
  message.textContent = "";
};
form.onsubmit = (event) => {
  event.preventDefault();
  run(review);
};
verify.onclick = () => run(async () => {
  await signIn({ options: "/sign-in/options", finish: "/sign-in/finish" });
  await review();
});
approve.onclick = () => run(async () => {
  if (!reviewed) return;
  await change("/cli/approve", reviewed);
  details.hidden = form.hidden = true;
  message.textContent = "Approved. Return to your terminal.";
});
