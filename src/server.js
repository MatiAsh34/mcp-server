import dotenv from "dotenv";
dotenv.config();
import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { executeQueryTool } from "./tools/executeQuery.js";
import { WorkOS } from "@workos-inc/node";

// ─────────────────────────────────────────────
// Logger util
// ─────────────────────────────────────────────
function log(level, tag, message, data = null) {
  const ts = new Date().toISOString();
  const prefix = `[${ts}] [${level.toUpperCase()}] [${tag}]`;
  if (data !== null) {
    console.log(`${prefix} ${message}`, typeof data === "object" ? JSON.stringify(data, null, 2) : data);
  } else {
    console.log(`${prefix} ${message}`);
  }
}

const workos = new WorkOS(process.env.WORKOS_API_KEY);

const AUTHKIT_DOMAIN = process.env.AUTHKIT_DOMAIN;
const MCP_SERVER_URL = process.env.MCP_SERVER_URL;

const JWKS = createRemoteJWKSet(
  new URL(`https://${AUTHKIT_DOMAIN}/oauth2/jwks`)
);

const MCP_RESOURCE_METADATA_URL = `${MCP_SERVER_URL}/.well-known/oauth-protected-resource/mcp`;

const WWW_AUTHENTICATE_HEADER = [
  'Bearer error="invalid_token"',
  'error_description="Authentication required for this tool"',
  `resource_metadata="${MCP_RESOURCE_METADATA_URL}"`,
].join(", ");

// Methods that don't require authentication
const PUBLIC_MCP_METHODS = new Set([
  "initialize",
  "notifications/initialized",
  "ping",
  "tools/list",
]);

function callsProtectedMethod(body) {
  const messages = Array.isArray(body) ? body : [body];
  for (const msg of messages) {
    if (!msg || typeof msg !== "object") continue;
    const method = msg.method;
    if (typeof method !== "string") continue;
    if (PUBLIC_MCP_METHODS.has(method)) continue;
    log("info", "AUTH", `Protected method detected: ${method}`);
    return true;
  }
  return false;
}

async function verifyToken(req) {
  const authHeader = req.headers.authorization;
  log("debug", "AUTH", `Authorization header: ${authHeader ? authHeader.substring(0, 30) + "..." : "MISSING"}`);

  const token = authHeader?.match(/^Bearer (.+)$/)?.[1];
  if (!token) {
    log("warn", "AUTH", "No Bearer token found in request");
    return null;
  }

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: `https://${AUTHKIT_DOMAIN}`,
    });
    log("info", "AUTH", `Token verified OK for sub: ${payload.sub}`);
    return payload;
  } catch (err) {
    log("error", "AUTH", `Token verification failed: ${err.message}`);
    return null;
  }
}

async function getEmailFromUserId(userId) {
  try {
    const user = await workos.userManagement.getUser(userId);
    log("info", "WORKOS", `User email resolved: ${user.email}`);
    return user.email;
  } catch (err) {
    log("error", "WORKOS", `Failed to get user by ID ${userId}: ${err.message}`);
    return null;
  }
}

async function isUserAllowed(userId, email) {
  const userDomain = email?.split("@")[1];
  log("info", "AUTHZ", `Checking authorization for ${email} (domain: ${userDomain})`);

  try {
    const organization = await workos.organizations.getOrganization(
      process.env.WORKOS_ALLOWED_ORG_ID
    );

    const orgDomains = organization.domains.map((d) => d.domain);
    log("debug", "AUTHZ", `Allowed org domains: ${orgDomains.join(", ")}`);

    if (orgDomains.includes(userDomain)) {
      log("info", "AUTHZ", `User ALLOWED via domain match: ${userDomain}`);
      return true;
    }

    const memberships = await workos.userManagement.listOrganizationMemberships({
      userId,
      organizationId: process.env.WORKOS_ALLOWED_ORG_ID,
      statuses: ["active"],
    });

    if (memberships.data.length > 0) {
      log("info", "AUTHZ", `User ALLOWED via org membership (${memberships.data.length} active)`);
      return true;
    }

    log("warn", "AUTHZ", `User DENIED — no domain match or active membership`);
  } catch (err) {
    log("error", "AUTHZ", `Authorization check failed: ${err.message}`);
  }

  return false;
}

function createMcpServer() {
  const server = new Server(
    { name: "postgres-mcp", version: "1.0.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    log("info", "MCP", "tools/list called — returning tool definitions");
    return {
      tools: [
        {
          name: executeQueryTool.name,
          description: "Ejecuta consultas SQL SELECT en PostgreSQL",
          inputSchema: {
            type: "object",
            properties: { query: { type: "string" } },
            required: ["query"],
          },
        },
      ],
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    log("info", "MCP", `Tool called: ${request.params.name}`, request.params.arguments);
    if (request.params.name === executeQueryTool.name) {
      const result = await executeQueryTool.handler(request.params.arguments);
      log("info", "MCP", `Tool ${request.params.name} completed`);
      return result;
    }
    throw new Error("Tool no encontrada");
  });

  return server;
}

// ─────────────────────────────────────────────
// Express app
// ─────────────────────────────────────────────
const app = express();
app.use(express.json());

// ── CORS — required for ChatGPT and other external MCP clients ──
app.use((req, res, next) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE");
  res.set("Access-Control-Allow-Headers", "Content-Type, Authorization, Mcp-Session-Id");
  res.set("Access-Control-Expose-Headers", "Mcp-Session-Id");

  if (req.method === "OPTIONS") {
    log("debug", "CORS", `OPTIONS preflight from ${req.headers.origin || "unknown"}`);
    return res.sendStatus(204);
  }
  next();
});

// ── Request logger middleware ──
app.use((req, _res, next) => {
  log("info", "HTTP", `${req.method} ${req.path}`, {
    userAgent: req.headers["user-agent"],
    origin: req.headers["origin"],
    contentType: req.headers["content-type"],
    hasAuth: !!req.headers["authorization"],
    body: req.method === "POST" ? req.body : undefined,
  });
  next();
});

// ─────────────────────────────────────────────
// OAuth / Resource discovery endpoints
// ─────────────────────────────────────────────

// Protected resource metadata — specific to /mcp
app.get("/.well-known/oauth-protected-resource/mcp", (_req, res) => {
  log("info", "DISCOVERY", "oauth-protected-resource/mcp requested");
  res.json({
    resource: MCP_SERVER_URL,
    authorization_servers: [`https://${AUTHKIT_DOMAIN}`],
    bearer_methods_supported: ["header"],
  });
});

// Protected resource metadata — generic (ChatGPT hits this first)
app.get("/.well-known/oauth-protected-resource", (_req, res) => {
  log("info", "DISCOVERY", "oauth-protected-resource requested");
  res.json({
    resource: MCP_SERVER_URL,
    authorization_servers: [`https://${AUTHKIT_DOMAIN}`],
    bearer_methods_supported: ["header"],
  });
});

// OAuth server metadata — proxied from WorkOS/AuthKit
app.get("/.well-known/oauth-authorization-server", async (_req, res) => {
  log("info", "DISCOVERY", "oauth-authorization-server requested — proxying to AuthKit");
  try {
    const response = await fetch(
      `https://${AUTHKIT_DOMAIN}/.well-known/oauth-authorization-server`
    );
    const data = await response.json();
    log("debug", "DISCOVERY", "AuthKit metadata fetched", {
      issuer: data.issuer,
      authorization_endpoint: data.authorization_endpoint,
      token_endpoint: data.token_endpoint,
      scopes_supported: data.scopes_supported,
    });
    res.json(data);
  } catch (err) {
    log("error", "DISCOVERY", `Failed to proxy oauth-authorization-server: ${err.message}`);
    res.status(502).json({ error: "Failed to fetch authorization server metadata" });
  }
});

// OpenID Connect discovery — some clients (including ChatGPT) try this path too
app.get("/.well-known/openid-configuration", async (_req, res) => {
  log("info", "DISCOVERY", "openid-configuration requested — proxying to AuthKit");
  try {
    const response = await fetch(
      `https://${AUTHKIT_DOMAIN}/.well-known/openid-configuration`
    );
    const data = await response.json();
    res.json(data);
  } catch (err) {
    log("error", "DISCOVERY", `Failed to proxy openid-configuration: ${err.message}`);
    res.status(502).json({ error: "Failed to fetch OpenID configuration" });
  }
});

// ─────────────────────────────────────────────
// MCP endpoint
// ─────────────────────────────────────────────

async function handleMcp(req, res) {
  const clientId = req.headers["mcp-session-id"] || "no-session";
  log("info", "MCP", `Handling ${req.method} /mcp — session: ${clientId}`);

  try {
    if (callsProtectedMethod(req.body)) {
      log("info", "AUTH", "Request requires authentication");
      const payload = await verifyToken(req);

      if (!payload) {
        log("warn", "AUTH", "Unauthenticated request to protected method — returning 401");
        return res
          .status(401)
          .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
          .json({
            error: "invalid_token",
            error_description: "Authentication required for this tool",
          });
      }

      const email = await getEmailFromUserId(payload.sub);
      if (!email) {
        log("warn", "AUTH", `Could not resolve email for sub: ${payload.sub}`);
        return res
          .status(401)
          .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
          .json({ error: "No se pudo obtener el email del usuario." });
      }

      const allowed = await isUserAllowed(payload.sub, email);
      if (!allowed) {
        log("warn", "AUTHZ", `User ${email} is not authorized`);
        return res
          .status(403)
          .set(
            "WWW-Authenticate",
            `Bearer error="insufficient_scope", resource_metadata="${MCP_RESOURCE_METADATA_URL}"`
          )
          .json({ error: "Usuario no autorizado." });
      }

      log("info", "AUTHZ", `User ${email} authorized — proceeding`);
    } else {
      log("info", "AUTH", "Request is public — skipping auth check");
    }

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });

    const server = createMcpServer();
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
    log("info", "MCP", `Request handled successfully — session: ${clientId}`);
  } catch (err) {
    log("error", "MCP", `Unhandled error: ${err.message}`, { stack: err.stack });
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32603, message: "Internal error" },
        id: null,
      });
    }
  }
}

// ChatGPT uses both POST (messages) and GET (SSE stream) on the same path
app.post("/mcp", handleMcp);
app.get("/mcp", handleMcp);

// ─────────────────────────────────────────────
// Health check
// ─────────────────────────────────────────────
app.get("/", (_req, res) => {
  log("debug", "HEALTH", "Health check hit");
  res.json({ ok: true, service: "postgres-mcp" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  log("info", "STARTUP", `MCP server running on port ${PORT}`);
  log("info", "STARTUP", `MCP endpoint:      ${MCP_SERVER_URL}/mcp`);
  log("info", "STARTUP", `Resource metadata: ${MCP_RESOURCE_METADATA_URL}`);
  log("info", "STARTUP", `AuthKit domain:    ${AUTHKIT_DOMAIN}`);
});