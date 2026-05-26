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
import { WorkOS } from "@workos-inc/node";

const workos = new WorkOS(process.env.WORKOS_API_KEY);

const AUTHKIT_DOMAIN = process.env.AUTHKIT_DOMAIN;
const MCP_SERVER_URL = process.env.MCP_SERVER_URL;

const JWKS = createRemoteJWKSet(
  new URL(`https://${AUTHKIT_DOMAIN}/oauth2/jwks`)
);

const MCP_RESOURCE_METADATA_URL = `${MCP_SERVER_URL}/.well-known/oauth-protected-resource/mcp`;

const WWW_AUTHENTICATE_HEADER = [
  `Bearer resource_metadata="${MCP_RESOURCE_METADATA_URL}"`,
  'error="invalid_token"',
  'error_description="Authentication required for this tool"',
].join(", ");

/**
 * Como tu única tool es privada, declaramos OAuth.
 *
 * Nota:
 * No usamos REQUIRED_SCOPES porque pediste no manejar scopes locales.
 * Tus scopes/metadata quedan delegados a los endpoints .well-known y a WorkOS/AuthKit.
 */
const TOOL_SECURITY_SCHEMES = [
  {
    type: "oauth2",
    scopes: [],
  },
];

/**
 * Métodos públicos para discovery/lifecycle.
 * Esto permite lazy auth: el cliente puede inicializar y listar tools sin token.
 */
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

    return true;
  }

  return false;
}

/**
 * Detecta si conviene usar el challenge MCP-style:
 *
 * ChatGPT necesita que el error de auth se devuelva como resultado de tool con:
 * _meta["mcp/www_authenticate"]
 *
 * Claude, en cambio, venía funcionando mejor con:
 * HTTP 401 + WWW-Authenticate
 *
 * Si el User-Agent no es confiable en tu entorno, podés forzar modo con env:
 *
 * MCP_AUTH_CHALLENGE_MODE=chatgpt  -> siempre _meta["mcp/www_authenticate"]
 * MCP_AUTH_CHALLENGE_MODE=claude   -> siempre HTTP 401
 * MCP_AUTH_CHALLENGE_MODE=hybrid   -> autodetecta por User-Agent
 */
function shouldUseMcpToolAuthChallenge(req) {
  const mode = process.env.MCP_AUTH_CHALLENGE_MODE || "hybrid";

  if (mode === "chatgpt") return true;
  if (mode === "claude") return false;

  const userAgent = req.headers["user-agent"] || "";

  return (
    userAgent.includes("ChatGPT") ||
    userAgent.includes("OpenAI") ||
    userAgent.includes("Mozilla")
  );
}

async function verifyToken(req) {
  const token = req.headers.authorization?.match(/^Bearer (.+)$/)?.[1];
  if (!token) return null;

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: `https://${AUTHKIT_DOMAIN}`,
    });

    return payload;
  } catch {
    return null;
  }
}

/**
 * Respuesta para ChatGPT lazy auth.
 *
 * Esto NO es HTTP 401.
 * Es un resultado MCP de la tool con _meta["mcp/www_authenticate"].
 */
function authRequiredToolResult(message = "Authentication required for this tool.") {
  return {
    content: [
      {
        type: "text",
        text: message,
      },
    ],
    _meta: {
      "mcp/www_authenticate": [WWW_AUTHENTICATE_HEADER],
    },
    isError: true,
  };
}

function forbiddenToolResult(message = "Usuario no autorizado.") {
  return {
    content: [
      {
        type: "text",
        text: message,
      },
    ],
    isError: true,
  };
}

async function getEmailFromUserId(userId) {
  try {
    const user = await workos.userManagement.getUser(userId);
    return user.email;
  } catch (err) {
    return null;
  }
}

async function isUserAllowed(userId, email) {
  const userDomain = email?.split("@")[1];

  try {
    const organization = await workos.organizations.getOrganization(
      process.env.WORKOS_ALLOWED_ORG_ID
    );

    const orgDomains = organization.domains.map((d) => d.domain);

    if (orgDomains.includes(userDomain)) {
      return true;
    }

    const memberships =
      await workos.userManagement.listOrganizationMemberships({
        userId,
        organizationId: process.env.WORKOS_ALLOWED_ORG_ID,
        statuses: ["active"],
      });

    if (memberships.data.length > 0) {
      return true;
    }
  } catch (err) {
    // Mantenemos tu comportamiento original:
    // si falla WorkOS o la consulta de org/membership, no autorizamos.
  }

  return false;
}

function createMcpServer(authContext = { ok: false, reason: "missing_token" }) {
  const server = new Server(
    { name: "postgres-mcp", version: "1.0.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: executeQueryTool.name,
        description: "Ejecuta consultas SQL SELECT en PostgreSQL",
        inputSchema: {
          type: "object",
          properties: {
            query: {
              type: "string",
            },
          },
          required: ["query"],
        },

        /**
         * Agregado para ChatGPT.
         * La tool es privada y requiere OAuth.
         */
        securitySchemes: TOOL_SECURITY_SCHEMES,

        /**
         * Mirror en _meta para clientes que leen securitySchemes desde _meta.
         */
        _meta: {
          securitySchemes: TOOL_SECURITY_SCHEMES,
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    if (request.params.name === executeQueryTool.name) {
      /**
       * Si llegamos acá sin auth válida, significa que estamos en modo ChatGPT
       * o modo MCP challenge.
       *
       * En modo Claude tradicional, ya habríamos respondido HTTP 401 antes
       * de llegar a este handler.
       */
      if (!authContext.ok) {
        if (authContext.reason === "forbidden") {
          return forbiddenToolResult("Usuario no autorizado.");
        }

        if (authContext.reason === "missing_email") {
          return authRequiredToolResult(
            "Authentication failed: no se pudo obtener el email del usuario."
          );
        }

        return authRequiredToolResult("Authentication required for this tool.");
      }

      return await executeQueryTool.handler(request.params.arguments);
    }

    throw new Error("Tool no encontrada");
  });

  return server;
}

const app = express();
app.use(express.json());

app.get("/.well-known/oauth-protected-resource/mcp", (_req, res) => {
  res.json({
    resource: MCP_SERVER_URL,
    authorization_servers: [`https://${AUTHKIT_DOMAIN}`],
    bearer_methods_supported: ["header"],
  });
});

app.get("/.well-known/oauth-protected-resource", (_req, res) => {
  res.json({
    resource: MCP_SERVER_URL,
    authorization_servers: [`https://${AUTHKIT_DOMAIN}`],
    bearer_methods_supported: ["header"],
  });
});

app.get("/.well-known/oauth-authorization-server", async (_req, res) => {
  const response = await fetch(
    `https://${AUTHKIT_DOMAIN}/.well-known/oauth-authorization-server`
  );

  res.json(await response.json());
});

app.post("/mcp", async (req, res) => {
  try {
    const useMcpToolAuthChallenge = shouldUseMcpToolAuthChallenge(req);

    let authContext = {
      ok: false,
      reason: "missing_token",
      payload: null,
      email: null,
    };

    if (callsProtectedMethod(req.body)) {
      const payload = await verifyToken(req);

      if (!payload) {
        /**
         * Claude-style:
         * respondemos HTTP 401 + WWW-Authenticate.
         *
         * ChatGPT-style:
         * NO cortamos el request; dejamos que tools/call devuelva
         * _meta["mcp/www_authenticate"].
         */
        if (!useMcpToolAuthChallenge) {
          return res
            .status(401)
            .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
            .json({
              error: "invalid_token",
              error_description: "Authentication required for this tool",
            });
        }

        authContext = {
          ok: false,
          reason: "missing_token",
          payload: null,
          email: null,
        };
      } else {
        const email = await getEmailFromUserId(payload.sub);

        if (!email) {
          if (!useMcpToolAuthChallenge) {
            return res
              .status(401)
              .set("WWW-Authenticate", WWW_AUTHENTICATE_HEADER)
              .json({ error: "No se pudo obtener el email del usuario." });
          }

          authContext = {
            ok: false,
            reason: "missing_email",
            payload,
            email: null,
          };
        } else {
          const allowed = await isUserAllowed(payload.sub, email);

          if (!allowed) {
            if (!useMcpToolAuthChallenge) {
              return res
                .status(403)
                .set(
                  "WWW-Authenticate",
                  `Bearer error="insufficient_scope", resource_metadata="${MCP_RESOURCE_METADATA_URL}"`
                )
                .json({ error: "Usuario no autorizado." });
            }

            authContext = {
              ok: false,
              reason: "forbidden",
              payload,
              email,
            };
          } else {
            authContext = {
              ok: true,
              reason: null,
              payload,
              email,
            };
          }
        }
      }
    }

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });

    const server = createMcpServer(authContext);
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32603, message: "Internal error" },
        id: null,
      });
    }
  }
});

app.get("/", (_req, res) => res.json({ ok: true, service: "postgres-mcp" }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`MCP server running on port ${PORT}`));