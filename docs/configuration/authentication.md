# Authentication

ReVa supports an optional API key to restrict access to its MCP server.

## API Key

The server does not require authentication by default. Set the **Server API Key** option in Ghidra's ReVa settings to enable simple API key authentication. When configured, all HTTP requests must include the API key using the `X-API-Key` header.

Clients connecting with the Model Context Protocol should send this header with each request. For example, using the Java `HttpClientStreamableHttpTransport` builder:

```java
HttpClientStreamableHttpTransport.builder(serverUrl)
    .endpoint("/mcp/message")
    .customizeRequest(req -> req.header("X-API-Key", "<your-api-key>"))
    .build();
```

If the header is missing or does not match, the server responds with `401 Unauthorized`.

To disable authentication, leave the **Server API Key** option empty.
