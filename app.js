// app.js — Rukus Health MyChart Connect
// Pure browser-side SMART on FHIR standalone launch with PKCE.
// No backend, no server-side code, no token storage except in your hands.

const PROVIDERS = {
  lexington: {
    name: "Lexington Medical Center",
    fhirBase: "https://lmcrcs.lexmed.com/FHIR/api/FHIR/R4",
    wellKnown: "https://lmcrcs.lexmed.com/FHIR/api/FHIR/R4/.well-known/smart-configuration",
  },
  prisma: {
    name: "Prisma Health",
    fhirBase: "https://epicproxy.et0915.epichosted.com/FHIRProxy/api/FHIR/R4",
    wellKnown: "https://epicproxy.et0915.epichosted.com/FHIRProxy/api/FHIR/R4/.well-known/smart-configuration",
  },
};

// Must match exactly what Epic on FHIR has for your app's redirect URI
const REDIRECT_URI = "https://rukka07.github.io/rukus-health/callback.html";

// Patient-facing scopes required for pulling labs
const SCOPES = "openid fhirUser offline_access launch/patient patient/Patient.read patient/Observation.read";

// client_id for rukka07's app — update after registering on open.epic.com
let CLIENT_ID = "fe110099-3a1f-4f45-ab9c-3231db89982c";


// --- PKCE helpers (RFC 7636) ---

function b64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256(plain) {
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);
  return await crypto.subtle.digest("SHA-256", data);
}

async function makePkce() {
  const verifierBytes = crypto.getRandomValues(new Uint8Array(32));
  const verifier = b64url(verifierBytes);
  const challenge = b64url(await sha256(verifier));
  return { verifier, challenge };
}

function randomState() {
  return b64url(crypto.getRandomValues(new Uint8Array(16)));
}


// --- SMART discovery ---

async function discoverEndpoints(provider) {
  const cfg = await fetch(provider.wellKnown, {
    headers: { "Accept": "application/json" }
  }).then(r => r.json());
  return {
    authorize: cfg.authorization_endpoint,
    token: cfg.token_endpoint,
  };
}


// --- Token exchange ---

async function exchangeCode(tokenUrl, code, verifier, clientId) {
  const params = new URLSearchParams({
    grant_type: "authorization_code",
    code: code,
    redirect_uri: REDIRECT_URI,
    client_id: clientId,
    code_verifier: verifier,
  });
  const resp = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Token exchange failed (${resp.status}): ${text}`);
  }
  const tokens = await resp.json();
  if (!tokens.access_token) {
    throw new Error("Token exchange returned no access_token: " + JSON.stringify(tokens));
  }
  return tokens;
}


// --- Main flow ---

async function startAuth() {
  if (!CLIENT_ID) {
    alert(
      "CLIENT_ID is not set.\n\n" +
      "You need to register this app on Epic on FHIR first.\n" +
      "1. Go to open.epic.com > My Apps > Create App\n" +
      "2. App type: Patient Facing\n" +
      "3. Select USCDI v3 APIs only\n" +
      "4. Redirect URI: " + REDIRECT_URI + "\n" +
      "5. Copy the Client ID and set CLIENT_ID in app.js"
    );
    return;
  }

  const providerKey = document.getElementById("provider").value;
  const provider = PROVIDERS[providerKey];
  const btn = document.getElementById("connectBtn");
  btn.disabled = true;
  btn.textContent = "Connecting...";

  try {
    const endpoints = await discoverEndpoints(provider);
    const pkce = await makePkce();
    const state = randomState();

    // Store PKCE + config in sessionStorage for the callback page
    sessionStorage.setItem("rukus_pkce", JSON.stringify({
      verifier: pkce.verifier,
      state: state,
      tokenUrl: endpoints.token,
      clientId: CLIENT_ID,
      providerName: provider.name,
      providerKey: providerKey,
      fhirBase: provider.fhirBase,
    }));

    const authParams = new URLSearchParams({
      response_type: "code",
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: SCOPES,
      state: state,
      aud: provider.fhirBase,
      code_challenge: pkce.challenge,
      code_challenge_method: "S256",
    });

    // Redirect to Epic MyChart login
    window.location.href = endpoints.authorize + "?" + authParams.toString();
  } catch (err) {
    alert("Failed to start login: " + err.message);
    btn.disabled = false;
    btn.textContent = "Connect to MyChart";
  }
}


// --- Utility ---

function copyTokens() {
  const ta = document.getElementById("output");
  ta.select();
  document.execCommand("copy");
}

function downloadTokens() {
  const raw = document.getElementById("output").value;
  const blob = new Blob([raw], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "epic_tokens.json";
  a.click();
  URL.revokeObjectURL(url);
}