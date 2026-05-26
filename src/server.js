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

const TOOL_SECURITY_SCHEMES = [
  {
    type: "oauth2",
    scopes: [],
  },
];

const PUBLIC_MCP_METHODS = new Set([
  "initialize",
  "notifications/initialized",
  "ping",
  "tools/list",
]);

/**
 * -------------------------
 * LOG HELPERS
 * -------------------------
 */

function nowIso() {
  return new Date().toISOString();
}

function getRequestId(req) {
  if (!req._mcpRequestId) {
    req._mcpRequestId =
      req.headers["x-request-id"] ||
      req.headers["cf-ray"] ||
      req.headers["x-vercel-id"] ||
      crypto.randomUUID?.() ||
      Math.random().toString(36).slice(2);
  }

  return req._mcpRequestId;
}

function getMcpMethods(body) {
  const messages = Array.isArray(body) ? body : [body];

  return messages
    .map((msg) => {
      if (!msg || typeof msg !== "object") return null;
      return msg.method || null;
    })
    .filter(Boolean);
}

function getMcpIds(body) {
  const messages = Array.isArray(body) ? body : [body];

  return messages
    .map((msg) => {
      if (!msg || typeof msg !== "object") return null;
      return msg.id ?? null;
    })
    .filter((id) => id !== null);
}

function getToolNames(body) {
  const messages = Array.isArray(body) ? body : [body];

  return messages
    .map((msg) => {
      if (!msg || typeof msg !== "object") return null;
      if (msg.method !== "tools/call") return null;
      return msg.params?.name || null;
    })
    .filter(Boolean);
}

function hasBearerToken(req) {
  return Boolean(req.headers.authorization?.match(/^Bearer\s+(.+)$/i));
}

function maskTokenFromHeader(authHeader) {
  const token = authHeader?.match(/^Bearer\s+(.+)$/i)?.[1];
  if (!token) return null;

  if (token.length <= 12) return "***";

  return `${token.slice(0, 6)}...${token.slice(-6)}`;
}

function logMcp(req, event, data = {}) {
  const requestId = getRequestId(req);

  console.log(
    JSON.stringify(
      {
        ts: nowIso(),
        event,
        requestId,
        ...data,
      },
      null,
      2
    )
  );
}

function logMcpError(req, event, err, data = {}) {
  const requestId = getRequestId(req);

  console.error(
    JSON.stringify(
      {
        ts: nowIso(),
        event,
        requestId,
        errorName: err?.name,
        errorMessage: err?.message,
        stack: process.env.LOG_STACKS === "true" ? err?.stack : undefined,
        ...data,
      },
      null,
      2
    )
  );
}

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
  const authHeader = req.headers.authorization;
  const token = authHeader?.match(/^Bearer (.+)$/)?.[1];

  logMcp(req, "auth.verify.start", {
    hasAuthHeader: Boolean(authHeader),
    hasBearerToken: Boolean(token),
    maskedToken: maskTokenFromHeader(authHeader),
  });

  if (!token) {
    logMcp(req, "auth.verify.missing_token");
    return null;
  }

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: `https://${AUTHKIT_DOMAIN}`,
    });

    logMcp(req, "auth.verify.success", {
      sub: payload.sub,
      iss: payload.iss,
      aud: payload.aud,
      scope: payload.scope,
      exp: payload.exp,
    });

    return payload;
  } catch (err) {
    logMcpError(req, "auth.verify.failed", err);
    return null;
  }
}

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

async function getEmailFromUserId(userId, req = null) {
  try {
    if (req) {
      logMcp(req, "workos.get_user.start", {
        userId,
      });
    }

    const user = await workos.userManagement.getUser(userId);

    if (req) {
      logMcp(req, "workos.get_user.success", {
        userId,
        email: user.email,
      });
    }

    return user.email;
  } catch (err) {
    if (req) {
      logMcpError(req, "workos.get_user.failed", err, {
        userId,
      });
    }

    return null;
  }
}

async function isUserAllowed(userId, email, req = null) {
  const userDomain = email?.split("@")[1];

  try {
    if (req) {
      logMcp(req, "authz.check.start", {
        userId,
        email,
        userDomain,
        organizationId: process.env.WORKOS_ALLOWED_ORG_ID,
      });
    }

    const organization = await workos.organizations.getOrganization(
      process.env.WORKOS_ALLOWED_ORG_ID
    );

    const orgDomains = organization.domains.map((d) => d.domain);

    if (req) {
      logMcp(req, "authz.organization.loaded", {
        organizationId: process.env.WORKOS_ALLOWED_ORG_ID,
        orgDomains,
      });
    }

    if (orgDomains.includes(userDomain)) {
      if (req) {
        logMcp(req, "authz.allowed_by_domain", {
          userDomain,
        });
      }

      return true;
    }

    const memberships =
      await workos.userManagement.listOrganizationMemberships({
        userId,
        organizationId: process.env.WORKOS_ALLOWED_ORG_ID,
        statuses: ["active"],
      });

    if (req) {
      logMcp(req, "authz.memberships.loaded", {
        userId,
        activeMembershipsCount: memberships.data.length,
      });
    }

    if (memberships.data.length > 0) {
      if (req) {
        logMcp(req, "authz.allowed_by_membership", {
          userId,
        });
      }

      return true;
    }
  } catch (err) {
    if (req) {
      logMcpError(req, "authz.check.failed", err, {
        userId,
        email,
      });
    }
  }

  if (req) {
    logMcp(req, "authz.denied", {
      userId,
      email,
      userDomain,
    });
  }

  return false;
}

function createMcpServer(authContext = { ok: false, reason: "missing_token" }, req = null) {
  const server = new Server(
    { name: "postgres-mcp", version: "1.0.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    if (req) {
      logMcp(req, "mcp.tools_list.handler", {
        toolName: executeQueryTool.name,
        securitySchemes: TOOL_SECURITY_SCHEMES,
      });
    }

    return {
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

          securitySchemes: TOOL_SECURITY_SCHEMES,

          _meta: {
            securitySchemes: TOOL_SECURITY_SCHEMES,
          },
        },
      ],
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    if (req) {
      logMcp(req, "mcp.tool_call.handler.start", {
        toolName: request.params.name,
        authOk: authContext.ok,
        authReason: authContext.reason,
        email: authContext.email,
      });
    }

    if (request.params.name === executeQueryTool.name) {
      if (!authContext.ok) {
        if (authContext.reason === "forbidden") {
          if (req) {
            logMcp(req, "mcp.tool_call.forbidden", {
              toolName: request.params.name,
              email: authContext.email,
            });
          }

          return forbiddenToolResult("Usuario no autorizado.");
        }

        if (authContext.reason === "missing_email") {
          if (req) {
            logMcp(req, "mcp.tool_call.auth_challenge", {
              toolName: request.params.name,
              reason: "missing_email",
              challengeType: "mcp_meta_www_authenticate",
              wwwAuthenticate: WWW_AUTHENTICATE_HEADER,
            });
          }

          return authRequiredToolResult(
            "Authentication failed: no se pudo obtener el email del usuario."
          );
        }

        if (req) {
          logMcp(req, "mcp.tool_call.auth_challenge", {
            toolName: request.params.name,
            reason: authContext.reason,
            challengeType: "mcp_meta_www_authenticate",
            wwwAuthenticate: WWW_AUTHENTICATE_HEADER,
          });
        }

        return authRequiredToolResult("Authentication required for this tool.");
      }

      if (req) {
        logMcp(req, "mcp.tool_call.execute", {
          toolName: request.params.name,
          email: authContext.email,
        });
      }

      const result = await executeQueryTool.handler(request.params.arguments);

      if (req) {
        logMcp(req, "mcp.tool_call.success", {
          toolName: request.params.name,
          email: authContext.email,
        });
      }

      return result;
    }

    if (req) {
      logMcp(req, "mcp.tool_call.not_found", {
        toolName: request.params.name,
      });
    }

    throw new Error("Tool no encontrada");
  });

  return server;
}

const app = express();
app.use(express.json());

app.get("/.well-known/oauth-protected-resource/mcp", (req, res) => {
  logMcp(req, "well_known.protected_resource_mcp", {
    userAgent: req.headers["user-agent"],
  });

  res.json({
    resource: MCP_SERVER_URL,
    authorization_servers: [`https://${AUTHKIT_DOMAIN}`],
    bearer_methods_supported: ["header"],
  });
});

app.get("/.well-known/oauth-protected-resource", (req, res) => {
  logMcp(req, "well_known.protected_resource", {
    userAgent: req.headers["user-agent"],
  });

  res.json({
    resource: MCP_SERVER_URL,
    authorization_servers: [`https://${AUTHKIT_DOMAIN}`],
    bearer_methods_supported: ["header"],
  });
});

app.get("/.well-known/oauth-authorization-server", async (req, res) => {
  try {
    logMcp(req, "well_known.authorization_server.start", {
      upstreamUrl: `https://${AUTHKIT_DOMAIN}/.well-known/oauth-authorization-server`,
      userAgent: req.headers["user-agent"],
    });

    const response = await fetch(
      `https://${AUTHKIT_DOMAIN}/.well-known/oauth-authorization-server`
    );

    const metadata = await response.json();

    logMcp(req, "well_known.authorization_server.success", {
      upstreamStatus: response.status,
      issuer: metadata.issuer,
      authorizationEndpoint: metadata.authorization_endpoint,
      tokenEndpoint: metadata.token_endpoint,
    });

    res.json(metadata);
  } catch (err) {
    logMcpError(req, "well_known.authorization_server.failed", err);

    res.status(502).json({
      error: "authorization_server_metadata_unavailable",
      error_description: "Could not fetch authorization server metadata.",
    });
  }
});

app.post("/mcp", async (req, res) => {
  try {
    const useMcpToolAuthChallenge = shouldUseMcpToolAuthChallenge(req);
    const protectedMethod = callsProtectedMethod(req.body);

    logMcp(req, "mcp.request.start", {
      httpMethod: req.method,
      path: req.path,
      userAgent: req.headers["user-agent"],
      hasAuthorization: hasBearerToken(req),
      maskedToken: maskTokenFromHeader(req.headers.authorization),
      authChallengeMode: process.env.MCP_AUTH_CHALLENGE_MODE || "hybrid",
      useMcpToolAuthChallenge,
      protectedMethod,
      mcpMethods: getMcpMethods(req.body),
      mcpIds: getMcpIds(req.body),
      toolNames: getToolNames(req.body),
    });

    let authContext = {
      ok: false,
      reason: "missing_token",
      payload: null,
      email: null,
    };

    if (protectedMethod) {
      logMcp(req, "mcp.auth.required", {
        useMcpToolAuthChallenge,
      });

      const payload = await verifyToken(req);

      if (!payload) {
        if (!useMcpToolAuthChallenge) {
          logMcp(req, "mcp.auth.challenge.http_401", {
            reason: "missing_or_invalid_token",
            wwwAuthenticate: WWW_AUTHENTICATE_HEADER,
          });

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

        logMcp(req, "mcp.auth.defer_to_tool_challenge", {
          reason: "missing_or_invalid_token",
          challengeType: "mcp_meta_www_authenticate",
        });
      } else {
        const email = await getEmailFromUserId(payload.sub, req);

        if (!email) {
          if (!useMcpToolAuthChallenge) {
            logMcp(req, "mcp.auth.challenge.http_401", {
              reason: "missing_email",
              wwwAuthenticate: WWW_AUTHENTICATE_HEADER,
            });

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

          logMcp(req, "mcp.auth.defer_to_tool_challenge", {
            reason: "missing_email",
            challengeType: "mcp_meta_www_authenticate",
          });
        } else {
          const allowed = await isUserAllowed(payload.sub, email, req);

          if (!allowed) {
            if (!useMcpToolAuthChallenge) {
              logMcp(req, "mcp.auth.challenge.http_403", {
                reason: "forbidden",
                email,
                wwwAuthenticate: `Bearer error="insufficient_scope", resource_metadata="${MCP_RESOURCE_METADATA_URL}"`,
              });

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

            logMcp(req, "mcp.auth.defer_to_tool_forbidden", {
              reason: "forbidden",
              email,
            });
          } else {
            authContext = {
              ok: true,
              reason: null,
              payload,
              email,
            };

            logMcp(req, "mcp.auth.success", {
              userId: payload.sub,
              email,
            });
          }
        }
      }
    } else {
      logMcp(req, "mcp.auth.not_required", {
        mcpMethods: getMcpMethods(req.body),
      });
    }

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });

    const server = createMcpServer(authContext, req);

    logMcp(req, "mcp.transport.connect.start", {
      authOk: authContext.ok,
      authReason: authContext.reason,
    });

    await server.connect(transport);

    logMcp(req, "mcp.transport.handle_request.start");

    await transport.handleRequest(req, res, req.body);

    logMcp(req, "mcp.request.completed", {
      headersSent: res.headersSent,
      statusCode: res.statusCode,
    });
  } catch (err) {
    logMcpError(req, "mcp.request.failed", err);

    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32603, message: "Internal error" },
        id: null,
      });
    }
  }
});

app.get("/", (req, res) => {
  logMcp(req, "root.healthcheck", {
    userAgent: req.headers["user-agent"],
  });

  res.json({ ok: true, service: "postgres-mcp" });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () =>
  console.log(
    JSON.stringify(
      {
        ts: nowIso(),
        event: "server.started",
        port: PORT,
        authChallengeMode: process.env.MCP_AUTH_CHALLENGE_MODE || "hybrid",
        mcpServerUrl: MCP_SERVER_URL,
        authkitDomain: AUTHKIT_DOMAIN,
      },
      null,
      2
    )
  )
);