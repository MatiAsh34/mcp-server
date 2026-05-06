import dotenv from "dotenv";
dotenv.config();

import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { executeQueryTool } from "./tools/executeQuery.js";


import { jwtVerify, createRemoteJWKSet } from 'jose';

const JWKS = createRemoteJWKSet(new URL('seamless-ice-72-staging.authkit.app/oauth2/jwks'));

const WWW_AUTHENTICATE_HEADER = [
  'Bearer error="unauthorized"',
  'error_description="Authorization needed"',
  `resource_metadata="https://mcp-server-rga9.onrender.com/mcp/.well-known/oauth-protected-resource"`,
].join(', ');

const bearerTokenMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.match(/^Bearer (.+)$/)?.[1];
  if (!token) {
    return res
      .set('WWW-Authenticate', WWW_AUTHENTICATE_HEADER)
      .status(401)
      .json({ error: 'No token provided.' });
  }

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: 'seamless-ice-72-staging.authkit.app',
      audience: 'https://mcp.example.com',
    });

    // Use access token claims to populate request context.
    // i.e. `req.userId = payload.sub;`

    next();
  } catch (err) {
    return res
      .set('WWW-Authenticate', WWW_AUTHENTICATE_HEADER)
      .status(401)
      .json({ error: 'Invalid bearer token.' });
  }
};

app.get('/.well-known/oauth-protected-resource', (req, res) =>
  res.json({
    resource: `https://mcp-server-rga9.onrender.com/mcp`,
    authorization_servers: ['https://seamless-ice-72-staging.authkit.app'],
    bearer_methods_supported: ['header'],
  }),
);

const app = express();
app.use(express.json());

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

app.post("/mcp", async (req, res) => {
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined, // stateless
  });

  const server = createMcpServer();

  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`MCP server corriendo en http://localhost:${PORT}/mcp`);
});