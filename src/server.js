import dotenv from "dotenv";
dotenv.config();

import express from "express";
import { jwtVerify, createRemoteJWKSet } from "jose";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { executeQueryTool } from "./tools/executeQuery.js";

const AUTHKIT_DOMAIN = process.env.WORKOS_AUTHKIT_DOMAIN;
const MCP_SERVER_URL = process.env.MCP_SERVER_URL;

const JWKS = createRemoteJWKSet(new URL(`${AUTHKIT_DOMAIN}/oauth2/jwks`));

const WWW_AUTHENTICATE_HEADER = [
  'Bearer error="unauthorized"',
  'error_description="Se requiere autorización"',
  `resource_metadata="${MCP_SERVER_URL}/.well-known/oauth-protected-resource"`,
].join(", ");

// ─── Middleware ───────────────────────────────────────────────────────────────

const bearerTokenMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.match(/^Bearer (.+)$/)?.[1];

  if (!token) {
    return res
      .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
      .status(401)
      .json({ error: "No se proporcionó token de autorización." });
  }

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: AUTHKIT_DOMAIN,
      audience: MCP_SERVER_URL,
    });

    req.authPayload = payload;
    next();
  } catch (err) {
    console.error("Token inválido:", err.message);
    return res
      .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
      .status(401)
      .json({ error: "Token Bearer inválido o expirado." });
  }
};

// ─── App ──────────────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());
// Needed to parse token exchange bodies from MCP clients
app.use(express.urlencoded({ extended: true }));

// ─── OAuth Discovery Endpoints ────────────────────────────────────────────────

/**
 * Protected Resource Metadata (RFC 9728)
 * Tells MCP clients that this is a resource server and points to the
 * authorization server.
 */
app.get("/.well-known/oauth-protected-resource", (req, res) => {
  res.json({
    resource: MCP_SERVER_URL,
    authorization_servers: [MCP_SERVER_URL], // ← apunta a NOSOTROS, no a WorkOS
    bearer_methods_supported: ["header"],
  });
});

/**
 * Authorization Server Metadata (RFC 8414)
 *
 * Claude Web busca este endpoint en el MISMO ORIGEN que el MCP server.
 * Devolvemos nuestra metadata pero con los endpoints de authorize/token
 * apuntando a nuestros propios proxies (/api/oauth/authorize y /api/oauth/token)
 * en lugar de directamente a WorkOS.
 */
app.get("/.well-known/oauth-authorization-server", async (req, res) => {
  try {
    const upstream = await fetch(
      `${AUTHKIT_DOMAIN}/.well-known/oauth-authorization-server`
    );
    const metadata = await upstream.json();

    // Sobreescribimos los endpoints para que apunten a nuestro proxy
    res.json({
      ...metadata,
      issuer: MCP_SERVER_URL,
      authorization_endpoint: `${MCP_SERVER_URL}/api/oauth/authorize`,
      token_endpoint: `${MCP_SERVER_URL}/api/oauth/token`,
    });
  } catch (err) {
    console.error("Error al obtener metadatos de AuthKit:", err.message);
    res.status(502).json({ error: "No se pudo obtener los metadatos del authorization server." });
  }
});

// ─── OAuth Proxy Endpoints ────────────────────────────────────────────────────

/**
 * Proxy de Authorize → WorkOS
 *
 * Claude Web redirige al usuario aquí. Nosotros hacemos un 302 hacia el
 * endpoint real de WorkOS, pasando todos los query params intactos.
 */
app.get("/api/oauth/authorize", (req, res) => {
  const upstreamUrl = new URL(`${AUTHKIT_DOMAIN}/oauth2/authorize`);

  // Reenviar todos los query params tal cual vienen del cliente MCP
  for (const [key, value] of Object.entries(req.query)) {
    upstreamUrl.searchParams.set(key, value);
  }

  console.log(`[OAuth] Authorize → ${upstreamUrl.toString()}`);
  res.redirect(302, upstreamUrl.toString());
});

/**
 * Proxy de Token → WorkOS
 *
 * Claude Web hace POST acá para intercambiar el code por un access token.
 * Nosotros reenviamos la request a WorkOS y devolvemos la respuesta al cliente.
 */
app.post("/api/oauth/token", async (req, res) => {
  try {
    const upstreamUrl = `${AUTHKIT_DOMAIN}/oauth2/token`;

    // Reconstruir el body como application/x-www-form-urlencoded
    // (que es lo que esperan los token endpoints de OAuth 2.x)
    const body = new URLSearchParams(req.body).toString();

    console.log(`[OAuth] Token exchange → ${upstreamUrl}`);

    const upstream = await fetch(upstreamUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        // Reenviar Authorization header si viene (client_secret_basic)
        ...(req.headers.authorization
          ? { Authorization: req.headers.authorization }
          : {}),
      },
      body,
    });

    const data = await upstream.json();

    res.status(upstream.status).json(data);
  } catch (err) {
    console.error("Error en token proxy:", err.message);
    res.status(502).json({ error: "Error al contactar el authorization server." });
  }
});

// ─── MCP Endpoint ─────────────────────────────────────────────────────────────

function createMcpServer() {
  const server = new Server(
    { name: "postgres-mcp", version: "1.0.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
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
    if (request.params.name === executeQueryTool.name) {
      return await executeQueryTool.handler(request.params.arguments);
    }
    throw new Error("Tool no encontrada");
  });

  return server;
}

app.post("/mcp", bearerTokenMiddleware, async (req, res) => {
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });

  const server = createMcpServer();

  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

// ─── Start ────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`MCP server corriendo en http://localhost:${PORT}/mcp`);
});