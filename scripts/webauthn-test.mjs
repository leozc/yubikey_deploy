// WebAuthn smoke test for a security key attached to this (remote) host, e.g.
// the virtual device fido-uhid-relay.py creates. Registers a throwaway,
// non-resident credential for rp "localhost" and signs in with it.
//
//   node webauthn-test.mjs            headless Chrome, driven over CDP;
//                                     touch-only (uv=discouraged by default)
//   node webauthn-test.mjs --gui      visible Chrome (needs a display, e.g.
//                                     `ssh -X`); click the button; Chrome's
//                                     own PIN prompt appears (uv=required)
// Options: --uv discouraged|preferred|required  --chrome BIN  --port N
// Prints one JSON line; exit code 0 when sign-in matched the registration.
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";

const { values: opt } = parseArgs({
  options: {
    gui: { type: "boolean", default: false },
    uv: { type: "string" },
    chrome: { type: "string", default: "google-chrome" },
    port: { type: "string", default: "8765" },
  },
});
const uv = opt.uv ?? (opt.gui ? "required" : "discouraged");
const port = Number(opt.port);

const PAGE = `<!doctype html><title>WebAuthn relay test</title>
<body style="font:20px system-ui;padding:2em">
<button id=b style="font-size:24px">Test security key (uv=${uv})</button><pre id=o></pre>
<script>
const rnd = n => crypto.getRandomValues(new Uint8Array(n));
const uvFlag = authData => (new Uint8Array(authData)[32] & 4) !== 0;
async function run() {
  const cred = await navigator.credentials.create({ publicKey: {
    rp: { name: "relay test", id: "localhost" },
    user: { id: rnd(16), name: "relay-test", displayName: "relay-test" },
    challenge: rnd(32),
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { userVerification: "${uv}", residentKey: "discouraged" },
    timeout: 90000 } });
  const got = await navigator.credentials.get({ publicKey: {
    challenge: rnd(32), rpId: "localhost",
    allowCredentials: [{ type: "public-key", id: cred.rawId }],
    userVerification: "${uv}", timeout: 90000 } });
  return { ok: got.id === cred.id,
           uvCreate: uvFlag(cred.response.getAuthenticatorData()),
           uvGet: uvFlag(got.response.authenticatorData) };
}
b.onclick = async () => {
  let r;
  try { r = await run(); } catch (e) { r = { ok: false, error: String(e) }; }
  o.textContent = JSON.stringify(r) + "\\n(you can close this window)";
  fetch("/result", { method: "POST", body: JSON.stringify(r) });
};
</script>`;

const profile = mkdtempSync(join(tmpdir(), "webauthn-test-"));
const server = http.createServer((req, res) => {
  if (req.method === "POST") {
    let body = "";
    req.on("data", c => (body += c));
    req.on("end", () => { res.end(); done(JSON.parse(body)); });
    return;
  }
  res.setHeader("content-type", "text/html");
  res.end(PAGE);
}).listen(port);

const chromeArgs = ["--no-first-run", "--no-default-browser-check", `--user-data-dir=${profile}`];
const chrome = opt.gui
  ? spawn(opt.chrome, [...chromeArgs, "--new-window", `http://localhost:${port}/`], { stdio: "ignore" })
  : spawn(opt.chrome, [...chromeArgs, "--headless=new", `--remote-debugging-port=${port + 1}`, "about:blank"], { stdio: "ignore" });
const chromeExited = new Promise(r => chrome.on("exit", r));

async function done(result) {
  console.log(JSON.stringify({ uv, ...result }));
  chrome.kill();
  await Promise.race([chromeExited, new Promise(r => setTimeout(r, 3000))]);
  rmSync(profile, { recursive: true, force: true });
  process.exit(result.ok ? 0 : 1);
}
setTimeout(() => done({ ok: false, error: "timed out after 240s" }), 240000);

if (opt.gui) {
  console.error(`click the button in the Chrome window (http://localhost:${port}/)`);
} else {
  let targets;
  for (let i = 0; i < 50 && !targets; i++) {
    await new Promise(r => setTimeout(r, 200));
    targets = await fetch(`http://127.0.0.1:${port + 1}/json/list`).then(r => r.json()).catch(() => null);
  }
  if (!targets) await done({ ok: false, error: `could not start ${opt.chrome}` });
  const ws = new WebSocket(targets.find(t => t.type === "page").webSocketDebuggerUrl);
  let id = 0;
  const pending = new Map();
  let loaded;
  const pageLoaded = new Promise(r => (loaded = r));
  ws.onmessage = m => {
    const d = JSON.parse(m.data);
    if (d.method === "Page.loadEventFired") loaded();
    pending.get(d.id)?.(d);
  };
  const send = (method, params = {}) =>
    new Promise(r => { pending.set(++id, r); ws.send(JSON.stringify({ id, method, params })); });
  await new Promise(r => (ws.onopen = r));
  await send("Page.enable");
  await send("Page.navigate", { url: `http://localhost:${port}/` });
  await pageLoaded;
  console.error("touch the security key when it blinks (register, then sign in)");
  const res = await send("Runtime.evaluate", {
    expression: "run().then(JSON.stringify)", awaitPromise: true, userGesture: true,
  });
  const exc = res.result?.exceptionDetails;
  await done(exc
    ? { ok: false, error: exc.exception?.description ?? exc.text }
    : JSON.parse(res.result.result.value));
}
