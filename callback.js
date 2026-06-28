// callback.js — Rukus Health OAuth callback handler
// Runs in the browser after Epic redirects back with an authorization code.

(function () {
  const statusEl = document.getElementById("status");
  const resultEl = document.getElementById("result");
  const outputEl = document.getElementById("output");

  // Parse the authorization code from the URL
  const params = new URLSearchParams(window.location.search);
  const code = params.get("code");
  const state = params.get("state");
  const error = params.get("error");

  if (error) {
    statusEl.className = "status error";
    statusEl.textContent = "Login error: " + error + (params.get("error_description") ? " — " + params.get("error_description") : "");
    return;
  }

  if (!code) {
    statusEl.className = "status error";
    statusEl.textContent = "No authorization code returned. Try again from the home page.";
    return;
  }

  // Recover PKCE params from sessionStorage
  let pkceData;
  try {
    pkceData = JSON.parse(sessionStorage.getItem("rukus_pkce"));
  } catch (_) {}
  if (!pkceData) {
    statusEl.className = "status error";
    statusEl.textContent = "Session expired or missing PKCE data. Start again from the login page.";
    return;
  }

  if (state !== pkceData.state) {
    statusEl.className = "status error";
    statusEl.textContent = "State mismatch — possible CSRF attack. Aborting.";
    return;
  }

  // Clear PKCE from sessionStorage now so it can't be reused
  sessionStorage.removeItem("rukus_pkce");

  // Exchange the authorization code for tokens
  exchangeCode(pkceData.tokenUrl, code, pkceData.verifier, pkceData.clientId)
    .then(tokens => {
      // Attach durable metadata for the Python connector
      tokens.token_url = pkceData.tokenUrl;
      tokens.fhir_base = pkceData.fhirBase;
      tokens.client_id = pkceData.clientId;
      tokens.provider = pkceData.providerKey;
      tokens.provider_name = pkceData.providerName;

      // Stamp expiry for the connector's refresh logic
      const now = Date.now() / 1000;
      tokens.expires_at = now + (tokens.expires_in || 3600);
      tokens.obtained_at = now;

      statusEl.textContent = "Connected to " + pkceData.providerName + ".";
      statusEl.className = "status";
      outputEl.value = JSON.stringify(tokens, null, 2);
      resultEl.style.display = "block";
    })
    .catch(err => {
      statusEl.className = "status error";
      statusEl.textContent = "Token exchange failed: " + err.message;
    });

  async function exchangeCode(tokenUrl, code, verifier, clientId) {
    const params = new URLSearchParams({
      grant_type: "authorization_code",
      code: code,
      redirect_uri: "https://rukka07.github.io/rukus-health/callback.html",
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
      throw new Error(`HTTP ${resp.status}: ${text}`);
    }
    const tokens = await resp.json();
    if (!tokens.access_token) {
      throw new Error("No access_token in response: " + JSON.stringify(tokens));
    }
    return tokens;
  }
})();

// Utility functions
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