# printspoofer

### Rust implementation of the printspoofer privilege escalation technique.
Creates a named pipe and listens for connections. Once an account connects, a primary token gets created from the impersonation token and cmd.exe is spawned in the context of the impersonated user.<br><br>
Compile with `cargo build`
<br><br>
Original research: [PrintSpoofer - Abusing Impersonation Privileges on Windows 10 and Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
<br>
Use can use [SpoolSample](https://github.com/leechristensen/SpoolSample) to force the SYSTEM account to connect to your named pipe.

![printspoofer](https://user-images.githubusercontent.com/27731554/182657831-016751d3-8053-491c-bfb1-3a31a58ba15e.gif)
