import { config } from "dotenv";
config({ path: ".env.local" });

import { Request, Response } from "express";
import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  getOAuthProtectedResourceMetadataUrl,
  mcpAuthMetadataRouter,
} from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import {
  isInitializeRequest,
  CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import { OAuthMetadata } from "@modelcontextprotocol/sdk/shared/auth.js";
import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";
import cors from "cors";

// Azure AD Configuration
const tenantId = process.env.AZURE_TENANT_ID || "";
const clientId = process.env.AZURE_CLIENT_ID || "";
const mcpServerUrl = new URL(
  process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`,
);

// JWKS client to fetch public keys from Azure AD
const jwksClient_ = jwksClient({
  jwksUri: `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`,
  cache: true,
  cacheMaxAge: 86400000,
});

// Create Azure AD OAuth metadata
const oauthMetadata: OAuthMetadata = {
  issuer: `https://login.microsoftonline.com/${tenantId}/v2.0`,
  authorization_endpoint: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`,
  token_endpoint: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
  jwks_uri: `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`,
  response_types_supported: ["code"],
  grant_types_supported: ["authorization_code"],
  token_endpoint_auth_methods_supported: [
    "client_secret_post",
    "client_secret_basic",
  ],
  scopes_supported: [`api://${clientId}/access`],
};

// Token verifier for Azure AD
const tokenVerifier = {
  verifyAccessToken: async (token: string) => {
    return new Promise<any>((resolve, reject) => {
      const getKey = (
        header: jwt.JwtHeader,
        callback: jwt.SigningKeyCallback,
      ) => {
        jwksClient_.getSigningKey(header.kid, (err, key) => {
          if (err) {
            callback(err);
            return;
          }
          const signingKey = key?.getPublicKey();
          callback(null, signingKey);
        });
      };

      jwt.verify(
        token,
        getKey,
        {
          audience: `api://${clientId}`,
          issuer: `https://sts.windows.net/${tenantId}/`,
          algorithms: ["RS256"],
        },
        (err, decoded) => {
          if (err) {
            console.log("❌ Token validation failed:", err.message);
            reject(new Error(`Invalid token: ${err.message}`));
            return;
          }

          console.log("✅ Token validated successfully");
          console.log("   Token claims:", JSON.stringify(decoded, null, 2));

          // Return AuthInfo format
          resolve({
            token,
            clientId: (decoded as any).appid || (decoded as any).azp,
            scopes: (decoded as any).scp ? (decoded as any).scp.split(" ") : [],
            expiresAt: (decoded as any).exp,
          });
        },
      );
    });
  },
};

// Create MCP Server instance
const getServer = () => {
  const server = new McpServer(
    {
      name: "azure-ad-mcp-server",
      version: "1.0.0",
    },
    {
      capabilities: { tools: {} },
    },
  );

  // Register tools
  server.registerTool(
    "echo",
    {
      description: "Echoes back the input text",
      inputSchema: {
        message: { type: "string", description: "The message to echo" },
      },
    },
    async ({ message }): Promise<CallToolResult> => {
      return {
        content: [{ type: "text", text: `Echo: ${message}` }],
      };
    },
  );

  server.registerTool(
    "get_time",
    {
      description: "Returns the current server time",
      inputSchema: {},
    },
    async (): Promise<CallToolResult> => {
      return {
        content: [
          {
            type: "text",
            text: `Current server time: ${new Date().toISOString()}`,
          },
        ],
      };
    },
  );

  server.registerTool(
    "greet",
    {
      description: "A simple greeting tool",
      inputSchema: {
        name: { type: "string", description: "Name to greet" },
      },
    },
    async ({ name }): Promise<CallToolResult> => {
      return {
        content: [
          {
            type: "text",
            text: `Hello, ${name}! Welcome to the Azure AD protected MCP server.`,
          },
        ],
      };
    },
  );

  return server;
};

const MCP_PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const HOST = process.env.HOST || "0.0.0.0";

const app = createMcpExpressApp({
  host: HOST,
  allowedHosts: ["localhost", "127.0.0.1", "192.168.1.165"],
});

// Enable CORS
app.use(
  cors({
    origin: true,
    credentials: true,
    methods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "mcp-session-id",
      "last-event-id",
    ],
  }),
);

// Request logging
app.use((req: Request, res: Response, next) => {
  const timestamp = new Date().toISOString();
  console.log(`\n${"=".repeat(80)}`);
  console.log(`[${timestamp}] ${req.method} ${req.url}`);
  console.log(`${"=".repeat(80)}`);
  console.log("Headers:", JSON.stringify(req.headers, null, 2));

  if (req.body && Object.keys(req.body).length > 0) {
    console.log("Body:", JSON.stringify(req.body, null, 2));
  }

  const originalSend = res.send;
  const originalJson = res.json;

  res.send = function (data: any) {
    console.log(`Response Status: ${res.statusCode}`);
    console.log("Response Headers:", JSON.stringify(res.getHeaders(), null, 2));
    if (data) {
      try {
        const bodyStr = typeof data === "string" ? data : JSON.stringify(data);
        console.log(
          "Response Body:",
          bodyStr.length > 1000
            ? bodyStr.substring(0, 1000) + "... (truncated)"
            : bodyStr,
        );
      } catch (e) {
        console.log("Response Body: [could not stringify]");
      }
    }
    console.log(`${"=".repeat(80)}\n`);
    return originalSend.call(this, data);
  };

  res.json = function (data: any) {
    console.log(`Response Status: ${res.statusCode}`);
    console.log("Response Headers:", JSON.stringify(res.getHeaders(), null, 2));
    console.log("Response Body (JSON):", JSON.stringify(data, null, 2));
    console.log(`${"=".repeat(80)}\n`);
    return originalJson.call(this, data);
  };

  next();
});

// Use SDK's metadata router with dynamic host detection
app.use((req: Request, res: Response, next) => {
  const protocol = req.protocol || "http";
  const host = req.get("host") || `localhost:${process.env.PORT || 3000}`;
  const baseUrl = new URL(`${protocol}://${host}`);
  const mcpUrl = new URL(`${protocol}://${host}/mcp`);

  const router = mcpAuthMetadataRouter({
    oauthMetadata: oauthMetadata,
    resourceServerUrl: mcpUrl,
    scopesSupported: [`api://${clientId}/access`],
    resourceName: "Azure AD MCP Server",
    bearerMethodsSupported: ["header"],
  });

  router(req, res, next);
});

// Create dynamic auth middleware that uses the request's host
const authMiddleware = (req: Request, res: Response, next: any) => {
  const protocol = req.protocol || "http";
  const host = req.get("host") || `localhost:${process.env.PORT || 3000}`;
  const baseUrl = new URL(`${protocol}://${host}`);

  console.log(`🔐 Auth middleware using: ${baseUrl.origin}`);
  console.log(`   Protocol: ${protocol}, Host header: ${req.get("host")}`);

  const middleware = requireBearerAuth({
    verifier: tokenVerifier,
    requiredScopes: [],
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(baseUrl),
  });

  middleware(req, res, next);
};

// Map to store transports by session ID
const transports: { [sessionId: string]: StreamableHTTPServerTransport } = {};

// MCP POST endpoint with auth
const mcpPostHandler = async (req: Request, res: Response) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  if (sessionId) {
    console.log(`\n📨 MCP POST for session: ${sessionId}`);
  } else {
    console.log("\n📨 MCP POST (new session)");
  }

  if (req.auth) {
    console.log("   Authenticated user:", req.auth);
  }

  try {
    let transport: StreamableHTTPServerTransport;
    if (sessionId && transports[sessionId]) {
      console.log("   ♻️  Reusing existing transport");
      transport = transports[sessionId];
    } else if (!sessionId && isInitializeRequest(req.body)) {
      console.log("   🆕 Creating new transport");

      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (sessionId) => {
          console.log(`   ✅ Session initialized: ${sessionId}`);
          transports[sessionId] = transport;
        },
      });

      transport.onclose = () => {
        const sid = transport.sessionId;
        if (sid && transports[sid]) {
          console.log(`   🔌 Session closed: ${sid}`);
          delete transports[sid];
        }
      };

      const server = getServer();
      await server.connect(transport);

      await transport.handleRequest(req, res, req.body);
      console.log("   ✅ Initialization complete");
      return;
    } else {
      console.log("   ❌ Invalid request");
      res.status(400).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Bad Request: No valid session ID" },
        id: null,
      });
      return;
    }

    await transport.handleRequest(req, res, req.body);
    console.log("   ✅ Request complete");
  } catch (error) {
    console.error("   ❌ Error:", error);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32603, message: "Internal server error" },
        id: null,
      });
    }
  }
};

app.post("/mcp", authMiddleware, mcpPostHandler);

// MCP GET endpoint (SSE)
const mcpGetHandler = async (req: Request, res: Response) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  if (!sessionId || !transports[sessionId]) {
    console.log("   ❌ Invalid session for SSE");
    res.status(400).send("Invalid or missing session ID");
    return;
  }

  const lastEventId = req.headers["last-event-id"] as string | undefined;
  if (lastEventId) {
    console.log(
      `\n📡 SSE reconnection for session ${sessionId} (Last-Event-ID: ${lastEventId})`,
    );
  } else {
    console.log(`\n📡 New SSE stream for session ${sessionId}`);
  }

  const transport = transports[sessionId];
  await transport.handleRequest(req, res);
};

app.get("/mcp", authMiddleware, mcpGetHandler);

// MCP DELETE endpoint
const mcpDeleteHandler = async (req: Request, res: Response) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  if (!sessionId || !transports[sessionId]) {
    res.status(400).send("Invalid or missing session ID");
    return;
  }

  console.log(`\n🗑️  DELETE session ${sessionId}`);

  try {
    const transport = transports[sessionId];
    await transport.handleRequest(req, res);
    console.log("   ✅ Session terminated");
  } catch (error) {
    console.error("   ❌ Error:", error);
    if (!res.headersSent) {
      res.status(500).send("Error processing session termination");
    }
  }
};

app.delete("/mcp", authMiddleware, mcpDeleteHandler);

// Health check
app.get("/health", (req: Request, res: Response) => {
  res.json({ status: "healthy", timestamp: new Date().toISOString() });
});

app.listen(MCP_PORT, HOST, () => {
  const baseUrl = mcpServerUrl.origin;
  console.log("\n" + "=".repeat(80));
  console.log("🚀 Azure AD MCP Server Started");
  console.log("=".repeat(80));
  console.log(`📍 Listening on: ${HOST}:${MCP_PORT}`);
  console.log(`📍 Server URL: ${baseUrl}`);
  console.log(`\n📡 Endpoints:`);
  console.log(`   • MCP (POST/GET/DELETE): ${baseUrl}/mcp`);
  console.log(`   • Health check:          ${baseUrl}/health`);
  console.log(
    `   • OAuth discovery:       ${baseUrl}/.well-known/oauth-authorization-server`,
  );
  console.log(
    `   • Resource metadata:     ${baseUrl}/.well-known/oauth-protected-resource`,
  );
  console.log(`\n🔐 Azure AD Configuration:`);
  console.log(`   • Tenant ID:  ${tenantId}`);
  console.log(`   • Client ID:  ${clientId}`);
  console.log(`   • Audience:   api://${clientId}`);
  console.log("=".repeat(80) + "\n");
  console.log("💡 Waiting for requests...\n");
});

// Cleanup on shutdown
process.on("SIGINT", async () => {
  console.log("\n\nShutting down...");
  for (const sessionId in transports) {
    try {
      await transports[sessionId].close();
      delete transports[sessionId];
    } catch (error) {
      console.error(`Error closing session ${sessionId}:`, error);
    }
  }
  console.log("Shutdown complete");
  process.exit(0);
});
