# Azure AD MCP Server with Streaming HTTP

A simple MCP (Model Context Protocol) server with Azure AD authentication using the official MCP SDK and streaming HTTP transport.

## Features

- Streaming HTTP transport
- Azure AD authentication middleware
- Two simple tools: `echo` and `get_time`
- Health check endpoint

## Setup

1. Install dependencies:
```bash
npm install
```

2. Configure Azure AD:
   - Create an Azure AD app registration
   - Copy `.env.example` to `.env`
   - Fill in your Azure AD credentials:
     - `AZURE_CLIENT_ID`: Your app's client ID
     - `AZURE_TENANT_ID`: Your Azure AD tenant ID
     - `AZURE_CLIENT_SECRET`: Your app's client secret

3. Run the server:
```bash
npm run dev
```

## Endpoints

- `POST /mcp` - Main MCP endpoint (requires Azure AD Bearer token)
- `GET /health` - Health check (no auth required)
- `GET /` - Server info (no auth required)

## Testing with Obot Proxy

To test this server through Obot proxy, you'll need to:

1. Start this server: `npm run dev`
2. Configure Obot proxy to forward requests to `http://localhost:3000/mcp`
3. Ensure the Azure AD token is passed in the Authorization header

## Available Tools

- **echo**: Echoes back the input message
- **get_time**: Returns the current server time in ISO format

## Authentication

The server expects a Bearer token in the Authorization header:
```
Authorization: Bearer <your-azure-ad-token>
```

The token is validated using Azure AD On-Behalf-Of flow.
