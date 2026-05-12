import dotenv from "dotenv";
dotenv.config();

import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { createRemoteJWKSet, jwtVerify } from "jose";

import { executeQueryTool } from "./tools/executeQuery.js";

// --- Config ---
const AUTHKIT_DOMAIN = process.env.WORKOS_AUTHKIT_DOMAIN;
const AUTHKIT_CLIENT_ID = process.env.AUTHKIT_CLIENT_ID;
const MCP_SERVER_URL = process.env.MCP_SERVER_URL;

// 🔧 BYPASS: ponés DEBUG_BYPASS_AUTH=true en las env vars de Render para saltear auth
const BYPASS_AUTH = process.env.DEBUG_BYPASS_AUTH === "true";

const JWKS = createRemoteJWKSet(
  new URL(`https://${AUTHKIT_DOMAIN}/oauth2/jwks`)
);

const WWW_AUTHENTICATE_HEADER = [
  'Bearer error="unauthorized"',
  'error_description="Authorization needed"',
  `resource_metadata="${MCP_SERVER_URL}/.well-known/oauth-protected-resource"`,
].join(", ");

// --- Helpers de log ---
function logRequest(tag, req) {
  console.log(`\n━━━ [${tag}] ${new Date().toISOString()} ━━━`);
  console.log(`  METHOD : ${req.method}`);
  console.log(`  PATH   : ${req.path}`);
  console.log(`  HEADERS:`);
  for (const [k, v] of Object.entries(req.headers)) {
    // Truncar tokens largos para legibilidad
    const val = k === "authorization" && v?.length > 80
      ? v.slice(0, 40) + "...[truncado]..." + v.slice(-10)
      : v;
    console.log(`    ${k}: ${val}`);
  }
  if (req.body && Object.keys(req.body).length > 0) {
    console.log(`  BODY   :`, JSON.stringify(req.body, null, 2).slice(0, 500));
  }
}

// --- Express App ---
const app = express();
app.use(express.json());

// --- Middleware de logging global ---
app.use((req, res, next) => {
  logRequest("INCOMING", req);
  const originalJson = res.json.bind(res);
  res.json = (body) => {
    console.log(`  ← RESPONSE ${res.statusCode}:`, JSON.stringify(body, null, 2).slice(0, 300));
    return originalJson(body);
  };
  next();
});

// --- Endpoint de diagnóstico (público) ---
app.get("/debug", async (req, res) => {
  console.log("[DEBUG] Endpoint de diagnóstico llamado");

  // Verificar que los endpoints de metadata de WorkOS respondan
  let asMetadata = null;
  let asMetadataError = null;
  try {
    const r = await fetch(`https://${AUTHKIT_DOMAIN}/.well-known/oauth-authorization-server`);
    asMetadata = await r.json();
  } catch (e) {
    asMetadataError = e.message;
  }

  let jwksStatus = null;
  let jwksError = null;
  try {
    const r = await fetch(`https://${AUTHKIT_DOMAIN}/oauth2/jwks`);
    const j = await r.json();
    jwksStatus = `OK - ${j.keys?.length ?? 0} key(s)`;
  } catch (e) {
    jwksError = e.message;
  }

  res.json({
    bypass_auth_active: BYPASS_AUTH,
    env: {
      AUTHKIT_DOMAIN: AUTHKIT_DOMAIN || "❌ NO SETEADA",
      AUTHKIT_CLIENT_ID: AUTHKIT_CLIENT_ID || "❌ NO SETEADA",
      MCP_SERVER_URL: MCP_SERVER_URL || "❌ NO SETEADA",
    },
    workos_as_metadata: asMetadata ?? { error: asMetadataError },
    jwks: jwksStatus ?? { error: jwksError },
    www_authenticate_header: WWW_AUTHENTICATE_HEADER,
  });
});

// --- Metadata Endpoints ---
app.get("/.well-known/oauth-protected-resource", (req, res) => {
  console.log("[oauth-protected-resource] Llamado por:", req.headers["user-agent"] ?? "unknown");
  res.json({
    resource: MCP_SERVER_URL,
    authorization_servers: [`https://${AUTHKIT_DOMAIN}`],
    bearer_methods_supported: ["header"],
  });
});

app.get("/.well-known/oauth-authorization-server", async (req, res) => {
  console.log("[oauth-authorization-server] Proxying a WorkOS...");
  try {
    const response = await fetch(
      `https://${AUTHKIT_DOMAIN}/.well-known/oauth-authorization-server`
    );
    const metadata = await response.json();
    console.log("[oauth-authorization-server] Metadata devuelta:", JSON.stringify(metadata, null, 2));
    res.json(metadata);
  } catch (err) {
    console.error("[oauth-authorization-server] ERROR:", err.message);
    res.status(502).json({ error: "Failed to fetch authorization server metadata" });
  }
});

// --- Middleware Bearer Token ---
async function bearerTokenMiddleware(req, res, next) {
  // 🔧 BYPASS MODE
  if (BYPASS_AUTH) {
    console.log("⚠️  [AUTH] BYPASS ACTIVO - saltando verificación de token");
    req.userId = "bypass-user";
    return next();
  }

  const authHeader = req.headers.authorization;
  console.log("[AUTH] Authorization header recibido:", authHeader ? "SÍ" : "NO");

  const token = authHeader?.match(/^Bearer (.+)$/)?.[1];

  if (!token) {
    console.log("[AUTH] ❌ No hay Bearer token → devolviendo 401");
    console.log("[AUTH] WWW-Authenticate enviado:", WWW_AUTHENTICATE_HEADER);
    return res
      .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
      .status(401)
      .json({ error: "No token provided." });
  }

  console.log("[AUTH] Token recibido, verificando con JWKS...");
  console.log("[AUTH] JWKS URL:", `https://${AUTHKIT_DOMAIN}/oauth2/jwks`);
  console.log("[AUTH] Issuer esperado:", `https://${AUTHKIT_DOMAIN}`);

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: `https://${AUTHKIT_DOMAIN}`,
    });

    console.log("[AUTH] ✅ Token válido");
    console.log("[AUTH] Payload:", {
      sub: payload.sub,
      iss: payload.iss,
      aud: payload.aud,
      exp: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
      iat: payload.iat ? new Date(payload.iat * 1000).toISOString() : null,
    });

    req.userId = payload.sub;
    next();
  } catch (err) {
    console.error("[AUTH] ❌ Error verificando token:", err.code ?? err.name, "-", err.message);
    return res
      .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
      .status(401)
      .json({ error: "Invalid bearer token.", detail: err.message });
  }
}

// --- Factory MCP Server ---
function createMcpServer() {
  const server = new Server(
    { name: "postgres-mcp", version: "1.0.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    console.log("[MCP] ListTools llamado");
    return {
      tools: [
        {
          name: executeQueryTool.name,
          description: "Ejecuta consultas SQL SELECT en PostgreSQL",
          inputSchema: {
            type: "object",
            properties: {
              query: { type: "string" },
            },
            required: ["query"],
          },
        },
      ],
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    console.log("[MCP] CallTool llamado:", request.params.name, "args:", request.params.arguments);
    if (request.params.name === executeQueryTool.name) {
      return await executeQueryTool.handler(request.params.arguments);
    }
    throw new Error("Tool no encontrada");
  });

  return server;
}

// --- Endpoint MCP ---
app.post("/mcp", bearerTokenMiddleware, async (req, res) => {
  console.log("[MCP] Request llegó al handler principal, userId:", req.userId);
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });

  const server = createMcpServer();

  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

// --- Iniciar servidor ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚀 MCP server corriendo en http://localhost:${PORT}/mcp`);
  console.log(`🔧 Modo bypass auth: ${BYPASS_AUTH ? "⚠️  ACTIVO" : "✅ desactivado"}`);
  console.log(`🌐 MCP_SERVER_URL: ${MCP_SERVER_URL}`);
  console.log(`🔑 AUTHKIT_DOMAIN: ${AUTHKIT_DOMAIN}`);
});