/*
 * Copyright (c) 2024-2025 The ReVa authors
 * SPDX-License-Identifier: Apache-2.0
 */

package reva.server;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

/**
 * HttpServletResponse wrapper that captures the response body for logging.
 * This allows the response to be written normally while also capturing
 * a copy for logging purposes.
 */
public class CachingResponseWrapper extends HttpServletResponseWrapper {

    private final ByteArrayOutputStream capture;
    private ServletOutputStream outputStream;
    private PrintWriter writer;

    public CachingResponseWrapper(HttpServletResponse response) {
        super(response);
        this.capture = new ByteArrayOutputStream();
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException {
        if (writer != null) {
            throw new IllegalStateException("getWriter() has already been called");
        }
        if (outputStream == null) {
            outputStream = new CachingServletOutputStream(super.getOutputStream(), capture);
        }
        return outputStream;
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        if (outputStream != null) {
            throw new IllegalStateException("getOutputStream() has already been called");
        }
        if (writer == null) {
            writer = new PrintWriter(new OutputStreamWriter(
                new CachingServletOutputStream(super.getOutputStream(), capture),
                StandardCharsets.UTF_8));
        }
        return writer;
    }

    @Override
    public void flushBuffer() throws IOException {
        if (writer != null) {
            writer.flush();
        } else if (outputStream != null) {
            outputStream.flush();
        }
        super.flushBuffer();
    }

    /**
     * Get the captured response body as a string.
     * @return The response body content
     */
    public String getCapturedBody() {
        return capture.toString(StandardCharsets.UTF_8);
    }

    /**
     * Get the captured response body as bytes.
     * @return The response body bytes
     */
    public byte[] getCapturedBodyBytes() {
        return capture.toByteArray();
    }

    /**
     * ServletOutputStream implementation that writes to both the original stream
     * and a capture buffer.
     */
    private static class CachingServletOutputStream extends ServletOutputStream {
        private final ServletOutputStream original;
        private final ByteArrayOutputStream capture;

        public CachingServletOutputStream(ServletOutputStream original, ByteArrayOutputStream capture) {
            this.original = original;
            this.capture = capture;
        }

        @Override
        public void write(int b) throws IOException {
            original.write(b);
            capture.write(b);
        }

        @Override
        public void write(byte[] b) throws IOException {
            original.write(b);
            capture.write(b);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            original.write(b, off, len);
            capture.write(b, off, len);
        }

        @Override
        public void flush() throws IOException {
            original.flush();
        }

        @Override
        public void close() throws IOException {
            original.close();
        }

        @Override
        public boolean isReady() {
            return original.isReady();
        }

        @Override
        public void setWriteListener(WriteListener writeListener) {
            original.setWriteListener(writeListener);
        }
    }
}
