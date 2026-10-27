Security Research: Critical SSRF & Open-Redirect Chain in Next.js Image Optimizer

Overview & Metadata
- Vulnerability Target: Next.js Image Optimizer (/_next/image) [≤15.4.2]
- Vulnerability Type: SSRF, Open Redirect Bypass, DNS Rebinding (TOCTOU), and Fallback Logic Data Leak
- CWE Classification: CWE-840 (Business Logic Errors) / CWE-918 (Server-Side Request Forgery)
- HackerOne Report Identifier: #3694648
- Status: Closed / Duplicate (Informative) of #3317603

Executive Summary
A critical multi-stage vulnerability chain was discovered in the Next.js Image Optimizer endpoint. By combining a TOCTOU DNS rebinding window, an open redirect bypass of remotePatterns validation, an XML-to-SVG magic byte collision, and a fallback exfiltration leak, an unauthenticated attacker could bypass network controls to exfiltrate raw internal infrastructure data and XML-returning cloud metadata services (such as AWS STS or instance metadata). Additionally, a secondary Denial of Service (DoS) vector via memory exhaustion (OOM) was identified.

Technical Attack Chain Analysis

1. DNS Rebinding SSRF (TOCTOU)
In packages/next/src/server/image-optimizer.ts, the initial IP check via dns.lookup is separated from the actual fetch() call. This creates a Time-of-Check to Time-of-Use window that permits DNS rebinding to bypass blocklists.

2. Open Redirect Bypass of remotePatterns
When an allowed domain responds with an HTTP redirect (301/302/307/308), the optimizer recursively follows the redirect URL without re-validating the destination against remotePatterns.

3. Magic Byte Collision (XML as SVG)
The detectContentType function evaluates initial buffer bytes:
If the sequence matches [0x3c, 0x3f, 0x78, 0x6d, 0x6c] (corresponding to the <?xml tag), the content is misclassified as image/svg+xml. This requires dangerouslyAllowSVG: true in next.config.js.

4. Fallback Exfiltration Leak
When Sharp optimization fails on the misclassified XML payload, the catch block triggers:
catch (error) {
  if (upstreamType) {
    return {
      buffer: upstreamBuffer, // RAW DATA EXFILTRATION
      contentType: upstreamType,
      error: error.message
    };
  }
}
Because upstreamType was flagged as an SVG, the raw internal buffer is returned directly in the HTTP response body.

Summary Validation Matrix

| Exploit Stage | Mechanism | Primary Impact |
| :--- | :--- | :--- |
| Stage 1 | DNS Rebinding / TOCTOU | Bypasses local/private IP restriction filters |
| Stage 2 | Open Redirect Follow-up | Bypasses remotePatterns domain enforcement |
| Stage 3 | Magic Byte Collision | Misclassifies internal XML data streams as SVG images |
| Stage 4 | Fallback Leak / OOM | Exfiltrates raw internal buffers or triggers worker exhaustion |

Remediation & Mitigation
- IP Pinning: Ensure the resolved IP address from the validation phase is passed directly to the fetch agent.
- Redirect Validation: Re-validate all intermediate and final redirect destinations against strict remotePatterns rules.
- Fallback Error Handling: Return standard error responses instead of raw buffers when optimization catches parsing failures.
- Version Fix: Addressed in Next.js 15.4.3.

