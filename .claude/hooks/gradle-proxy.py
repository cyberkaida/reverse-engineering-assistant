#!/usr/bin/env python3
"""Local CONNECT proxy that forwards to an authenticated upstream proxy.

Gradle/JVM cannot use the https_proxy env var with authentication directly.
This script runs a local unauthenticated proxy on 127.0.0.1:18080 that
forwards requests to the upstream authenticated proxy, adding the required
Proxy-Authorization header automatically.
"""
import base64
import os
import socket
import threading
import sys
import urllib.parse

UPSTREAM_PROXY_URL = os.environ.get("https_proxy", os.environ.get("HTTPS_PROXY", ""))
LOCAL_PORT = 18080


def parse_proxy_url(url):
    parsed = urllib.parse.urlparse(url)
    user = urllib.parse.unquote(parsed.username or "")
    password = urllib.parse.unquote(parsed.password or "")
    host = parsed.hostname
    port = parsed.port or 3128
    return host, port, user, password


def relay(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try:
            src.close()
        except Exception:
            pass
        try:
            dst.close()
        except Exception:
            pass


def handle_client(client_sock, upstream_host, upstream_port, proxy_auth_header):
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = client_sock.recv(4096)
            if not chunk:
                client_sock.close()
                return
            data += chunk

        header_end = data.index(b"\r\n\r\n")
        header_bytes = data[:header_end]
        rest = data[header_end + 4:]

        first_line = header_bytes.split(b"\r\n")[0]
        method = first_line.split(b" ")[0].decode()

        if method == "CONNECT":
            target = first_line.split(b" ")[1].decode()

            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            upstream.connect((upstream_host, upstream_port))

            connect_req = (
                f"CONNECT {target} HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"Proxy-Authorization: Basic {proxy_auth_header}\r\n"
                f"\r\n"
            )
            upstream.sendall(connect_req.encode())

            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = upstream.recv(4096)
                if not chunk:
                    client_sock.close()
                    upstream.close()
                    return
                resp += chunk

            resp_line = resp.split(b"\r\n")[0]
            status_code = int(resp_line.split(b" ")[1])

            if status_code == 200:
                client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                t1 = threading.Thread(target=relay, args=(client_sock, upstream), daemon=True)
                t2 = threading.Thread(target=relay, args=(upstream, client_sock), daemon=True)
                t1.start()
                t2.start()
                t1.join()
                t2.join()
            else:
                client_sock.sendall(resp)
                client_sock.close()
                upstream.close()
        else:
            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            upstream.connect((upstream_host, upstream_port))

            lines = header_bytes.split(b"\r\n")
            new_lines = [lines[0]]
            for line in lines[1:]:
                if not line.lower().startswith(b"proxy-authorization:"):
                    new_lines.append(line)
            new_lines.append(f"Proxy-Authorization: Basic {proxy_auth_header}".encode())
            new_header = b"\r\n".join(new_lines) + b"\r\n\r\n" + rest
            upstream.sendall(new_header)

            t1 = threading.Thread(target=relay, args=(client_sock, upstream), daemon=True)
            t2 = threading.Thread(target=relay, args=(upstream, client_sock), daemon=True)
            t1.start()
            t2.start()
            t1.join()
            t2.join()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        try:
            client_sock.close()
        except Exception:
            pass


def main():
    if not UPSTREAM_PROXY_URL:
        print("No https_proxy set", file=sys.stderr)
        sys.exit(1)

    upstream_host, upstream_port, user, password = parse_proxy_url(UPSTREAM_PROXY_URL)
    proxy_auth_header = base64.b64encode(f"{user}:{password}".encode()).decode()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", LOCAL_PORT))
    server.listen(50)

    print(f"Local proxy listening on 127.0.0.1:{LOCAL_PORT}", file=sys.stderr)
    print(f"Forwarding to {upstream_host}:{upstream_port}", file=sys.stderr)

    while True:
        client_sock, _ = server.accept()
        t = threading.Thread(
            target=handle_client,
            args=(client_sock, upstream_host, upstream_port, proxy_auth_header),
            daemon=True,
        )
        t.start()


if __name__ == "__main__":
    main()
