# Playbook: network-and-c2

Copy each Mandatory thread into the plan with the five fields.

## Done-when

- Transport: protocol (TCP, UDP, HTTP, HTTPS, DNS, pipe) and library, with the call site.
- Every address (domain, IP, URL, port, path), with how it is obtained (static, decoded, generated, resolved) and its producer.
- Framing: request and response layout (headers, lengths, magic, encoding, encryption).
- The code that uses it: each handler, named in the database.

## Mandatory threads

1. `transport`. Question: which protocol and library carry the traffic? Start: the first network import's caller. Closes when: the send and receive calls are read. Must exist: a function name at each send and receive wrapper.
2. `address-<NN>`, one per address or source. Question: where does this address come from? Start: the call that uses it, and the fallback path. Closes when: the producer is read (Callee rule): literal, decoder, generator or lookup. Must exist: a comment at the producer: `<address> — static | decoded | generated | resolved`.
3. `framing`. Question: what bytes are sent and received? Start: the buffer passed to the send call. Closes when: its builder and the response parser are read. Must exist: a structure applied to the buffer, or a comment at the builder listing each field.
4. `commands`. Question: what can the operator make it do? Start: the branch on received bytes. Closes when: every branch's handler is read. Must exist: a function name at each handler; a comment at the dispatch listing each command value.

## Platform notes

| Platform | Where the network code is |
|---|---|
| Windows PE | `WinHttpSendRequest`, `InternetOpenUrlW`, `HttpSendRequestW`, `WSAStartup`, `connect`, `DnsQuery_W`; `\\.\pipe\` names; BITS and `IWinHttpRequest` through `CoCreateInstance`. |
| macOS Mach-O | `NSURLSession`, `CFStreamCreatePairWithSocketToHost`, `nw_connection_create`, `getaddrinfo`, `socket`. |
| Linux ELF | `socket`, `connect`, `send`, `getaddrinfo`; libcurl `curl_easy_setopt`; `curl` or `wget` command strings. |
| Embedded firmware and raw images | lwIP `lwip_connect`, `tcp_connect`; vendor SDK sockets; MQTT topics; modem `AT+` command strings. |
| Shellcode and position-independent blobs | No imports: hashed names for `WSASocketA` or `InternetOpenA`; `syscall` numbers (`connect` is 42 on x86-64 Linux); IP and port as immediates in a `sockaddr_in` (family `2`, port big-endian). |
| Managed and bytecode runtimes | .NET `HttpClient`, `WebClient`, `TcpClient`; Java `HttpURLConnection`, OkHttp; Go `net/http`, `net.Dial`; Python `requests`, `urllib`, `socket`. |

## Common wrong conclusions

| Jump | Check |
|---|---|
| "A compromised legitimate site, so not the C2." | A site it fetches commands or a payload from is the C2. Report it as C2, full URL. |
| "The URLs in the strings are the C2." | Decoys exist: trace each address from the network call to its producer. |
| "HTTPS, so the protocol cannot be recovered." | The buffer is built before the TLS call: read the builder. |
| "No network: no socket imports." | Check run-time loaders (`GetProcAddress`, `dlsym`), API hashes, COM, child processes (`curl`, `powershell`). Write `no network: read <functions>; checked <imports, strings>`. |
