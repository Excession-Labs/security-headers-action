# HTTP Security Headers Grader

A GitHub Action that grades the HTTP security headers of one or more URLs. Run it after a deploy, against staging or production, and fail the job when a header is missing or weak.

The action makes its own requests from the runner. It calls no external API and has no dependencies. It reads response headers only and never stores the page body.

## What it checks

The rules come from the OWASP Secure Headers Project and MDN. Each check returns pass, warn, fail or info.

| Id | Check | Fails or warns when |
| --- | --- | --- |
| https | HTTPS | The final page is served over plain http |
| hsts | Strict-Transport-Security | Missing, max-age is 0 (fail), or under 31536000 seconds (warn) |
| csp | Content-Security-Policy | Missing (fail), Report-Only only, no script-src or default-src, `unsafe-inline` without a nonce or hash, `unsafe-eval`, wildcard script sources, or no object-src (warn) |
| framing | Clickjacking protection | Neither CSP `frame-ancestors` nor X-Frame-Options is set (fail), or `frame-ancestors` has a wildcard (warn) |
| nosniff | X-Content-Type-Options | Missing or not `nosniff` |
| referrer | Referrer-Policy | Missing or lenient (warn), `unsafe-url` (fail) |
| permissions | Permissions-Policy | Missing (warn) |
| coop | Cross-Origin-Opener-Policy | Reported as info only |
| leaks | Version disclosure | `Server` with a version number, `X-Powered-By`, `X-AspNet-Version`, `X-Generator` (warn) |
| cors | CORS on this page | Credentials allowed cross-origin (warn), otherwise info |
| xxss | X-XSS-Protection | Set to anything but 0 (info, deprecated) |
| cookies | Cookie flags | A cookie lacks `Secure` on https or an explicit `SameSite` (warn) |

The checker sends one GET request per redirect hop, follows up to 5 redirects and waits up to 8 seconds per request by default. HSTS is graded as a failure on plain http because the header has no effect there.

## Usage

```yaml
name: headers
on:
  deployment_status:
  workflow_dispatch:

jobs:
  headers:
    runs-on: ubuntu-latest
    steps:
      - uses: Excession-Labs/security-headers-action@v1
        with:
          urls: |
            https://staging.example.com
            https://www.example.com
          fail-on: fail
```

Check a local server started earlier in the same job:

```yaml
      - run: npm start &
      - uses: Excession-Labs/security-headers-action@v1
        with:
          urls: http://localhost:3000
          ignore: https hsts
```

Use the JSON output in a later step:

```yaml
      - id: headers
        uses: Excession-Labs/security-headers-action@v1
        with:
          urls: https://www.example.com
          fail-on: none
      - run: echo '${{ steps.headers.outputs.summary }}' | jq '.totals'
```

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `urls` | required | URLs to check, one per line. Any http or https URL, including localhost. Lines that start with `#` are skipped. |
| `fail-on` | `fail` | `fail` fails the step on any failed check or unreachable URL. `warn` also fails on warnings. `none` never fails. |
| `timeout` | `8` | Seconds to wait for each request, from 1 to 60. |
| `ignore` | empty | Check ids to leave out, separated by commas or spaces, for example `https hsts` for a local server. |

## Outputs

| Output | Description |
| --- | --- |
| `summary` | JSON with `result`, `totals` and the full result of every check for every URL. |
| `result` | Overall result: `pass`, `warn` or `fail`. An unreachable URL counts as `fail`. |

The action also writes a Markdown report to the job summary and adds an annotation for each failed or warned check.

## Sample job summary

```text
## HTTP security headers

| URL | Result | Pass | Warn | Fail |
| --- | --- | --- | --- | --- |
| https://www.example.com | WARN | 5 | 2 | 0 |

### https://www.example.com

| Check | Status | Value | Note |
| --- | --- | --- | --- |
| HTTPS | PASS | `https` | Reached over https. |
| Strict-Transport-Security | PASS | `max-age=31536000; includeSubDomains` | Set with max-age of at least one year. |
| Permissions-Policy | WARN |  | Missing. It lets you turn off browser features the site does not use, such as camera, microphone and geolocation. |
```

The values above are an illustration of the format, not a real scan.

## Limits

- The action reads response headers of one page per URL. It does not crawl a site and does not test application logic.
- It is not a penetration test. A passing result means the headers follow the rules in the table, not that the application is secure.
- Headers can differ by path, by user agent and by whether a user is signed in. The action requests the URL you give it, without cookies.
- It runs on a runner with Node 24 (`runs.using: node24`). A URL must be reachable from that runner.

## Related

- Free web checker with the same rules: https://penetrationtestservices.com/tools/security-headers-checker/
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- MDN HTTP headers reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers

## Development

```sh
node --test test/*.test.js
```

The tests start local HTTP servers with known headers and run the action entry point with the same `INPUT_` variables the runner passes.

## License

MIT. The check rules are ported from the header checker of Excession Labs, also MIT.
