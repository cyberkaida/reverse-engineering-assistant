/*
 * Copyright (c) 2024-2025 The ReVa authors
 * SPDX-License-Identifier: Apache-2.0
 */

package reva.server;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * HttpServletRequest wrapper that caches the request body for logging.
 * This allows the request body to be read multiple times - once for logging
 * and once for the actual servlet processing.
 */
public class CachingRequestWrapper extends HttpServletRequestWrapper {

    private byte[] cachedBody;

    public CachingRequestWrapper(HttpServletRequest request) throws IOException {
        super(request);
        cacheInputStream(request.getInputStream());
    }

    private void cacheInputStream(InputStream inputStream) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            baos.write(buffer, 0, bytesRead);
        }
        cachedBody = baos.toByteArray();
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        return new CachedServletInputStream(cachedBody);
    }

    @Override
    public BufferedReader getReader() throws IOException {
        return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
    }

    /**
     * Get the cached request body as a string.
     * @return The request body content
     */
    public String getCachedBody() {
        return new String(cachedBody, StandardCharsets.UTF_8);
    }

    /**
     * Get the cached request body as bytes.
     * @return The request body bytes
     */
    public byte[] getCachedBodyBytes() {
        return cachedBody;
    }

    /**
     * ServletInputStream implementation that reads from cached bytes.
     */
    private static class CachedServletInputStream extends ServletInputStream {
        private final ByteArrayInputStream inputStream;

        public CachedServletInputStream(byte[] cachedBody) {
            this.inputStream = new ByteArrayInputStream(cachedBody);
        }

        @Override
        public int read() throws IOException {
            return inputStream.read();
        }

        @Override
        public boolean isFinished() {
            return inputStream.available() == 0;
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setReadListener(ReadListener readListener) {
            throw new UnsupportedOperationException("ReadListener not supported");
        }
    }
}
