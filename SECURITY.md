# Security Policy

## Reporting a Vulnerability

**OhmZ** is a network scanner that operates with raw sockets and elevated privileges. We hold ourselves to a high standard and appreciate your efforts to responsibly disclose your findings.

### Reporting Process

**DO NOT** create public GitHub issues for security vulnerabilities.

Instead, please report security vulnerabilities by emailing:

```
security@effront.gg
```

### What to Include

Please include the following information in your report:

- **Type of vulnerability** (e.g., command injection, memory corruption, privilege escalation, packet injection)
- **Full path** of the affected source file(s)
- **Location** of the affected code (file path, line number, commit hash)
- **Step-by-step instructions** to reproduce the issue
- **Proof-of-concept or exploit code** (if possible)
- **Impact** of the vulnerability
- **Suggested fix** (if you have one)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution Target**: Depends on severity (see below)

### Severity Levels

| Severity | Response Time | Examples |
|----------|---------------|----------|
| **Critical** | 24-48 hours | RCE via crafted packet response, memory corruption in packet parser, SYN cookie bypass |
| **High** | 3-7 days | Privilege escalation, buffer overflow in header parsing, IP spoofing bypass |
| **Medium** | 7-14 days | Information disclosure via timing attacks, unsafe memory in output handlers |
| **Low** | 14-30 days | Verbose error messages, minor information leakage in scan reports |

## Security Architecture

OhmZ implements security measures to protect both the operator and scanned targets:

### Memory Safety
- Zig's explicit allocator model with `GeneralPurposeAllocator` leak detection
- No hidden allocations - every allocation is visible and tracked
- Compile-time size verification for packet headers via `comptime` assertions
- Bounded buffers for all network I/O operations

### Packet Handling
- `extern struct` for IP and TCP headers with compile-time layout guarantees
- Pre-built packet templates - only variable fields are patched per target
- Checksum computation for every outgoing packet (IP + TCP)
- Input validation on all received packet headers before processing

### Stateless Validation
- SYN cookies via SipHash-2-4 with cryptographically random keys (via `getrandom`)
- Cookie validation prevents response spoofing from non-target hosts
- No per-connection state stored during scanning

### Rate Control
- 256-bucket sliding window throttle prevents network flooding
- Adaptive batch sizing with overshoot detection
- Suspend detection resets rate after long pauses

### Code Quality
- `zig fmt` enforced on every push
- Unit tests for all core modules (stats, target, packet, cookie, blackrock, throttle)
- Static binary with no external dependencies
- CI workflows: `ci.yml` and `security-scan.yml`

## Ethical Use

OhmZ is designed exclusively for **authorized security testing and network reconnaissance**:

- Always obtain written authorization before scanning any target
- Respect rate limits and avoid disrupting target networks
- Never scan targets without explicit permission
- Findings are for defensive purposes only
- Comply with all applicable local, national, and international laws

Unauthorized use of OhmZ against systems you do not own or have permission to test is illegal and unethical. The authors assume no liability for misuse.

## Security Considerations for Contributors

When contributing to OhmZ:

1. **Memory safety** - use Zig's allocator model correctly, no unbounded buffers
2. **Packet validation** - validate all fields from received packets before use
3. **No credential storage** - scan results must never contain credentials or sensitive data
4. **Rate limiting** - all scan modes must respect the configured rate limit
5. **Error handling** - never expose internal memory state in error output
6. **Raw socket safety** - minimize privilege surface, validate socket options

### Before committing code:

```bash
zig fmt src/ build.zig       # Fix formatting
zig build test               # Unit tests
zig build -Doptimize=ReleaseSafe  # Release build check
```

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Safe Harbor

OhmZ provides a safe harbor for security researchers who:

- Make a good faith effort to avoid privacy violations, data destruction, and service disruption
- Only interact with accounts you own or with explicit permission
- Do not exploit a vulnerability beyond the minimum necessary to demonstrate it
- Report vulnerabilities promptly
- Give us reasonable time to fix the issue before any public disclosure

We will not pursue legal action against researchers who follow this policy.

## Out of Scope

The following are explicitly **out of scope** for vulnerability reports:

- Social engineering attacks against maintainers
- Denial of Service (DoS/DDoS) against project infrastructure
- Vulnerabilities in third-party dependencies (report to their maintainers directly)
- Issues requiring physical access to the operator's machine
- Vulnerabilities in outdated or unsupported versions
- Scan results from authorized testing (that is the tool's intended purpose)

## Contact

- **Security Team**: security@effront.gg
- **GitHub Issues**: For non-security bugs only

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1)

---

**Last Updated**: 2026-11-08
**Policy Version**: 1.0
