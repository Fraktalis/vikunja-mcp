/**
 * Password-gated OAuth 2.1 provider for MCP (Express adaptation).
 *
 * Implements a self-contained OAuth 2.1 flow:
 * - Claude connects -> gets 401 with metadata pointer
 * - Claude discovers /.well-known/oauth-protected-resource
 * - Claude registers via /oauth/register (DCR)
 * - Claude redirects user to /oauth/authorize
 * - User sees a password page, enters MCP_AUTH_TOKEN
 * - Claude exchanges code for access token via /oauth/token
 * - All subsequent requests carry Bearer token
 *
 * No external identity provider needed.
 */

import { randomUUID, randomBytes, createHash, timingSafeEqual } from "crypto";
import { readFile, writeFile, mkdir, chmod } from "fs/promises";
import { dirname } from "path";
import type { Application } from "express";

interface PendingAuth {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  state: string;
  code: string;
  createdAt: number;
}

interface TokenRecord {
  accessToken: string;
  refreshToken: string;
  clientId: string;
  expiresAt: number;
  refreshExpiresAt: number;
}

interface RegisteredClient {
  clientId: string;
  clientSecret: string;
  redirectUris: string[];
  clientName?: string;
}

const TOKEN_EXPIRY_MS = 3600 * 1000; // 1 hour
const DEFAULT_REFRESH_DAYS = 14;
const REFRESH_EXPIRY_MS =
  (parseInt(process.env.MCP_REFRESH_DAYS ?? String(DEFAULT_REFRESH_DAYS)) ||
    DEFAULT_REFRESH_DAYS) *
  24 *
  3600 *
  1000;
const MAX_FAILED_BEFORE_LOCKOUT = 5;
const BASE_LOCKOUT_MS = 5 * 1000; // 5 seconds, doubles each lockout
const MAX_CLIENTS = 100;
const MAX_PENDING = 100;
const PENDING_TTL_MS = 10 * 60 * 1000; // 10 minutes

export interface AuthHandle {
  validateToken: (auth: string | undefined) => boolean;
  saveTokens: () => Promise<void>;
  loadTokens: () => Promise<boolean>;
  cleanup: () => void;
}

export function mountPasswordAuth(
  app: Application,
  baseUrl: string,
  password: string,
  persistPath?: string
): AuthHandle {
  const pendingAuths = new Map<string, PendingAuth>();
  const csrfTokens = new Map<string, string>();
  const tokens = new Map<string, TokenRecord>();
  const refreshTokens = new Map<string, TokenRecord>();
  const clients = new Map<string, RegisteredClient>();

  function cleanupPending() {
    const now = Date.now();
    for (const [code, pending] of pendingAuths) {
      if (now - pending.createdAt > PENDING_TTL_MS) {
        pendingAuths.delete(code);
        csrfTokens.delete(code);
      }
    }
  }

  let failedAttempts = 0;
  let lockoutCount = 0;
  let lockedUntil = 0;

  if (!baseUrl.startsWith("https://") && !baseUrl.includes("localhost")) {
    console.warn(
      "WARNING: BASE_URL is not HTTPS. OAuth tokens will be sent in cleartext. Use a tunnel (cloudflared, tailscale, ngrok) to provide TLS."
    );
  }

  // --- Discovery endpoints ---

  app.get("/.well-known/oauth-protected-resource", (_req, res) => {
    res.json({
      resource: baseUrl,
      authorization_servers: [baseUrl],
      scopes_supported: ["mcp"],
    });
  });

  app.get("/.well-known/oauth-authorization-server", (_req, res) => {
    res.json({
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/oauth/authorize`,
      token_endpoint: `${baseUrl}/oauth/token`,
      registration_endpoint: `${baseUrl}/oauth/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "none"],
      scopes_supported: ["mcp"],
    });
  });

  // --- Dynamic Client Registration (RFC 7591) ---

  app.post("/oauth/register", (req, res) => {
    if (clients.size >= MAX_CLIENTS) {
      res.status(429).json({ error: "too_many_clients" });
      return;
    }
    const body = req.body as Record<string, unknown>;

    const redirectUris = Array.isArray(body.redirect_uris)
      ? (body.redirect_uris as unknown[]).slice(0, 5)
      : [];
    if (redirectUris.length === 0) {
      res.status(400).json({
        error: "invalid_client_metadata",
        error_description: "redirect_uris required",
      });
      return;
    }
    const safeUri = (u: unknown) => {
      if (typeof u !== "string" || u.length > 2048) return false;
      const lower = u.toLowerCase();
      return (
        !lower.startsWith("javascript:") &&
        !lower.startsWith("data:") &&
        !lower.startsWith("file:")
      );
    };
    if (redirectUris.some((u) => !safeUri(u))) {
      res.status(400).json({
        error: "invalid_client_metadata",
        error_description: "invalid redirect_uri",
      });
      return;
    }

    const clientId = randomUUID();
    const clientSecret = randomBytes(32).toString("hex");
    const clientName =
      typeof body.client_name === "string"
        ? body.client_name.slice(0, 256)
        : undefined;

    const client: RegisteredClient = {
      clientId,
      clientSecret,
      redirectUris: redirectUris as string[],
      clientName,
    };
    clients.set(clientId, client);

    res.status(201).json({
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uris: client.redirectUris,
      client_name: client.clientName,
      token_endpoint_auth_method: "client_secret_post",
    });
  });

  // --- Authorization endpoint ---

  app.get("/oauth/authorize", (req, res) => {
    const clientId = (req.query["client_id"] as string) ?? "";
    const redirectUri = (req.query["redirect_uri"] as string) ?? "";
    const codeChallenge = (req.query["code_challenge"] as string) ?? "";
    const codeChallengeMethod =
      (req.query["code_challenge_method"] as string) ?? "S256";
    const state = (req.query["state"] as string) ?? "";

    const client = clients.get(clientId);
    if (!client) {
      res.status(400).send("Unknown client");
      return;
    }
    if (!client.redirectUris.includes(redirectUri)) {
      res.status(400).send("Invalid redirect URI");
      return;
    }
    if (codeChallengeMethod !== "S256" || !codeChallenge) {
      res.status(400).send("PKCE with S256 is required");
      return;
    }

    cleanupPending();
    if (pendingAuths.size >= MAX_PENDING) {
      res.status(429).send("Too many pending authorizations");
      return;
    }

    const code = randomBytes(32).toString("hex");
    pendingAuths.set(code, {
      clientId,
      redirectUri,
      codeChallenge,
      codeChallengeMethod,
      state,
      code,
      createdAt: Date.now(),
    });

    const csrf = randomBytes(32).toString("hex");
    csrfTokens.set(code, csrf);
    res.send(renderPasswordPage(code, csrf));
  });

  // --- Approval handler ---

  app.post("/oauth/approve", (req, res) => {
    const body = req.body as Record<string, string>;
    const code = body["code"] ?? "";
    const submittedCsrf = body["csrf"] ?? "";
    const submittedPassword = body["password"] ?? "";

    const pending = pendingAuths.get(code);
    const expectedCsrf = csrfTokens.get(code);
    if (!pending || !expectedCsrf) {
      res
        .status(400)
        .send("<p>Invalid or expired authorization request.</p>");
      return;
    }

    const csrfA = Buffer.from(submittedCsrf);
    const csrfB = Buffer.from(expectedCsrf);
    if (csrfA.length !== csrfB.length || !timingSafeEqual(csrfA, csrfB)) {
      res.status(403).send("<p>Invalid request.</p>");
      return;
    }

    if (Date.now() < lockedUntil) {
      const waitSec = Math.ceil((lockedUntil - Date.now()) / 1000);
      console.warn(`Auth: locked out, ${waitSec}s remaining`);
      const newCsrf = randomBytes(32).toString("hex");
      csrfTokens.set(code, newCsrf);
      res
        .status(429)
        .send(
          renderPasswordPage(
            code,
            newCsrf,
            `Too many attempts. Try again in ${waitSec} seconds.`
          )
        );
      return;
    }

    const a = Buffer.from(submittedPassword);
    const b = Buffer.from(password);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      failedAttempts++;
      console.warn(`Auth: failed attempt ${failedAttempts} total`);

      const newCsrf = randomBytes(32).toString("hex");
      csrfTokens.set(code, newCsrf);

      if (failedAttempts >= MAX_FAILED_BEFORE_LOCKOUT) {
        lockoutCount = Math.min(lockoutCount + 1, 10);
        const lockoutMs = BASE_LOCKOUT_MS * Math.pow(2, lockoutCount - 1);
        lockedUntil = Date.now() + lockoutMs;
        console.warn(`Auth: lockout #${lockoutCount}, ${lockoutMs / 1000}s`);
        res
          .status(429)
          .send(
            renderPasswordPage(
              code,
              newCsrf,
              `Too many attempts. Try again in ${Math.ceil(lockoutMs / 1000)} seconds.`
            )
          );
        return;
      }

      res.status(401).send(renderPasswordPage(code, newCsrf, "Wrong password."));
      return;
    }

    failedAttempts = 0;
    lockoutCount = 0;
    lockedUntil = 0;
    csrfTokens.delete(code);
    console.log("Auth: password accepted, issuing authorization code.");

    const url = new URL(pending.redirectUri);
    url.searchParams.set("code", code);
    if (pending.state) url.searchParams.set("state", pending.state);
    res.redirect(url.toString());
  });

  // --- Token endpoint ---

  app.post("/oauth/token", (req, res) => {
    const body = req.body as Record<string, string>;
    const grantType = body["grant_type"] ?? "";

    if (grantType === "authorization_code") {
      const code = body["code"] ?? "";
      const clientId = body["client_id"] ?? "";
      const codeVerifier = body["code_verifier"] ?? "";
      const redirectUri = body["redirect_uri"] ?? "";

      const pending = pendingAuths.get(code);
      if (!pending || Date.now() - pending.createdAt > PENDING_TTL_MS) {
        if (pending) pendingAuths.delete(code);
        res.status(400).json({ error: "invalid_grant" });
        return;
      }

      if (clientId !== pending.clientId) {
        res.status(400).json({
          error: "invalid_grant",
          error_description: "client_id mismatch",
        });
        return;
      }

      if (redirectUri !== pending.redirectUri) {
        res.status(400).json({
          error: "invalid_grant",
          error_description: "redirect_uri mismatch",
        });
        return;
      }

      if (pending.codeChallengeMethod === "S256") {
        const expected = createHash("sha256")
          .update(codeVerifier)
          .digest("base64url");
        if (expected !== pending.codeChallenge) {
          res.status(400).json({
            error: "invalid_grant",
            error_description: "PKCE verification failed",
          });
          return;
        }
      }

      pendingAuths.delete(code);

      const accessToken = randomBytes(32).toString("hex");
      const refreshToken = randomBytes(32).toString("hex");
      const record: TokenRecord = {
        accessToken,
        refreshToken,
        clientId: pending.clientId,
        expiresAt: Date.now() + TOKEN_EXPIRY_MS,
        refreshExpiresAt: Date.now() + REFRESH_EXPIRY_MS,
      };
      tokens.set(accessToken, record);
      refreshTokens.set(refreshToken, record);

      res.json({
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: TOKEN_EXPIRY_MS / 1000,
        refresh_token: refreshToken,
      });
      return;
    }

    if (grantType === "refresh_token") {
      const refreshToken = body["refresh_token"] ?? "";
      const old = refreshTokens.get(refreshToken);
      if (!old) {
        res.status(400).json({ error: "invalid_grant" });
        return;
      }

      if (Date.now() > old.refreshExpiresAt) {
        tokens.delete(old.accessToken);
        refreshTokens.delete(refreshToken);
        console.log("Auth: refresh token expired, user must re-authenticate.");
        res.status(400).json({
          error: "invalid_grant",
          error_description: "Refresh token expired",
        });
        return;
      }

      tokens.delete(old.accessToken);
      refreshTokens.delete(refreshToken);

      const accessToken = randomBytes(32).toString("hex");
      const newRefreshToken = randomBytes(32).toString("hex");
      const record: TokenRecord = {
        accessToken,
        refreshToken: newRefreshToken,
        clientId: old.clientId,
        expiresAt: Date.now() + TOKEN_EXPIRY_MS,
        refreshExpiresAt: old.refreshExpiresAt,
      };
      tokens.set(accessToken, record);
      refreshTokens.set(newRefreshToken, record);

      res.json({
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: TOKEN_EXPIRY_MS / 1000,
        refresh_token: newRefreshToken,
      });
      return;
    }

    res.status(400).json({ error: "unsupported_grant_type" });
  });

  return {
    validateToken(authHeader: string | undefined): boolean {
      if (!authHeader?.startsWith("Bearer ")) return false;
      const token = authHeader.slice(7);
      const record = tokens.get(token);
      if (!record) return false;
      if (Date.now() > record.expiresAt) {
        tokens.delete(token);
        return false;
      }
      return true;
    },

    async saveTokens(): Promise<void> {
      if (!persistPath) return;
      try {
        await mkdir(dirname(persistPath), { recursive: true });
        const now = Date.now();
        const activeTokens = [...tokens.entries()].filter(
          ([, r]) => r.expiresAt > now
        );
        const activeRefresh = [...refreshTokens.entries()].filter(
          ([, r]) => r.refreshExpiresAt > now
        );
        const data = JSON.stringify({
          tokens: Object.fromEntries(activeTokens),
          refreshTokens: Object.fromEntries(activeRefresh),
          clients: Object.fromEntries(clients),
        });
        await writeFile(persistPath, data, { encoding: "utf-8", mode: 0o600 });
        await chmod(persistPath, 0o600);
        console.log(`Auth tokens saved to disk (${tokens.size} sessions).`);
      } catch (err) {
        console.error("Failed to save auth tokens:", err);
      }
    },

    cleanup(): void {
      const now = Date.now();
      for (const [k, r] of tokens) {
        if (r.expiresAt <= now) tokens.delete(k);
      }
      for (const [k, r] of refreshTokens) {
        if (r.refreshExpiresAt <= now) refreshTokens.delete(k);
      }
      const activeClientIds = new Set<string>();
      for (const r of tokens.values()) activeClientIds.add(r.clientId);
      for (const r of refreshTokens.values()) activeClientIds.add(r.clientId);
      for (const [k, c] of clients) {
        if (!activeClientIds.has(c.clientId)) clients.delete(k);
      }
    },

    async loadTokens(): Promise<boolean> {
      if (!persistPath) return false;
      try {
        const raw = await readFile(persistPath, "utf-8");
        const data = JSON.parse(raw) as {
          tokens?: Record<string, TokenRecord>;
          refreshTokens?: Record<string, TokenRecord>;
          clients?: Record<string, RegisteredClient>;
        };
        const now = Date.now();
        for (const [k, v] of Object.entries(data.tokens ?? {})) {
          if (v.accessToken && v.refreshToken && v.expiresAt > now)
            tokens.set(k, v);
        }
        for (const [k, v] of Object.entries(data.refreshTokens ?? {})) {
          if (v.accessToken && v.refreshToken && v.refreshExpiresAt > now)
            refreshTokens.set(k, v);
        }
        for (const [k, v] of Object.entries(data.clients ?? {})) {
          if (v.clientId && v.redirectUris) clients.set(k, v);
        }
        console.log(
          `Auth tokens loaded from disk (${tokens.size} sessions).`
        );
        return tokens.size > 0;
      } catch {
        return false;
      }
    },
  };
}

function renderPasswordPage(
  code: string,
  csrf: string,
  error?: string
): string {
  const esc = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const escAttr = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/"/g, "&quot;");
  return `<!DOCTYPE html>
<html><head><title>Vikunja MCP - Authorize</title>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<style>
  body { font-family: system-ui; max-width: 400px; margin: 80px auto; padding: 0 20px; }
  h1 { font-size: 1.3em; }
  input[type=password] { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; font-size: 1em; }
  button { padding: 10px 20px; font-size: 1em; cursor: pointer; }
  .error { color: red; }
</style></head>
<body>
  <h1>Vikunja MCP</h1>
  ${error ? `<p class="error">${esc(error)}</p>` : "<p>Enter the server password to authorize access to Vikunja.</p>"}
  <form method="POST" action="/oauth/approve" autocomplete="on">
    <input type="hidden" name="code" value="${escAttr(code)}">
    <input type="hidden" name="csrf" value="${escAttr(csrf)}">
    <input type="text" name="username" id="username" value="vikunja-mcp" autocomplete="username" style="position:absolute;opacity:0;width:1px;height:1px;pointer-events:none">
    <input type="password" name="password" id="password" placeholder="Password" autocomplete="current-password" autofocus required>
    <br><button type="submit">Authorize</button>
  </form>
</body></html>`;
}
