# datum-mask

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-brightgreen.svg)](https://nodejs.org)
[![Zero-Dependencies](https://img.shields.io/badge/Dependencies-0-orange.svg)](#)

> **Deterministic, streaming PII scrubber and dataset anonymizer preserving relational integrity.**

---

## 🎯 The Problem
Engineering teams frequently need production-like datasets for staging, local testing, and analytics debugging. Random mocking tools like Faker break foreign-key relationships, UUID cross-references, and categorical cardinality across multi-table or distributed log exports. Conversely, naive hashing leaks structural patterns or creates invalid schemas. datum-mask provides deterministic, format-preserving pseudorandom data masking over streaming JSONL and CSV pipelines with zero npm dependencies, keyed HMAC-SHA256 hashing, and low memory overhead.

## ✨ Key Features
- **Zero External Dependencies**: Pure Node.js runtime primitives.
- **Production Grade**: Linted, exception-guarded, and CI/CD-friendly.
- **Fast Execution**: Minimal footprint with microsecond overhead.

# datum-mask

Deterministic, zero-dependency streaming PII scrubber and dataset anonymizer designed for production databases, data warehouse extracts, and staging pipelines.

## The Problem
When staging environments or local test databases are seeded with production copies, compliance standards (GDPR, HIPAA, SOC2) strictly prohibit raw Personally Identifiable Information (PII).

Existing tools typically fail in two ways:
1. **Random Mock Generators (e.g. Faker)**: Replace IDs and emails with random strings. This completely destroys foreign key relationships, cross-table joins, and log correlation between services.
2. **Naive Hashing**: Destroys formats (e.g. valid email, RFC-compliant UUID, IPv4 octets), which causes strict schema validation and database constraints to fail.

`datum-mask` uses a keyed HMAC-SHA256 engine to achieve **deterministic pseudorandom anonymization** with **format preservation**, while streaming multi-gigabyte files with tiny memory usage.

## Features
- **Strict Referential Integrity**: An ID, email, or token mapped under secret key `K` will consistently resolve to the same synthetic pseudonym across disparate tables and log files.
- **Zero External Dependencies**: Built 100% on native Node.js streams, crypto, and readline APIs.
- **High Performance & Streaming**: Operates with O(1) memory overhead over unbounded NDJSON/JSONL and CSV streams.
- **Native Gzip Support**: Stream directly to and from gzipped dumps via `--gzip`.
- **Format Preserving**: Outputs valid RFC-4122 UUIDs, valid RFC-1918 private IPv4 addresses, parseable synthetic email domains, and preserved phone digit masks.

## Installation

Clone and link globally or execute directly:
```bash
git clone https://github.com/example/datum-mask.git
cd datum-mask
npm link
```

Or run with Node directly:
```bash
node src/cli.js --help
```

## CLI Usage & Options

| Option | Alias | Description |
| :--- | :--- | :--- |
| `--secret <key>` | `-s` | HMAC master seed. Defaults to `DATUM_SECRET` environment variable. |
| `--format <fmt>` | `-f` | Format type: `jsonl` (default) or `csv`. |
| `--rules <spec>` | `-r` | Comma-separated field rule mappings (`col:rule,col2:rule`). |
| `--auto-detect` | `-a` | Auto-detect email, IPv4, UUID, and phone strings in unmapped JSON fields. |
| `--input <path>` | `-i` | Input file path (defaults to standard input). |
| `--output <path>` | `-o` | Output file path (defaults to standard output). |
| `--gzip` | | Decompress input and compress output on-the-fly. |
| `--help` | `-h` | Display usage instructions. |

### Supported Rule Types
- `email`: Formats to `<hmac>@<hmac>.<tld>`.
- `ip` / `ipv4`: Maps deterministically to the RFC 1918 `10.x.x.x` private subnet.
- `uuid`: Generates valid v4-formatted deterministic UUIDs.
- `phone`: Preserves punctuation while deterministically scrambling phone digits.
- `redact`: Static `[REDACTED]` replacement.
- `string`: Format-preserving alphanumeric permutation.

## Real-World Examples

### 1. Scrubbing a JSONL event dump via STDIN
```bash
cat production-events.jsonl \
  | datum-mask \
      --secret "ci-staging-salt-9182" \
      --rules "user_id:uuid,client_ip:ip,contact_email:email" \
  > staging-events.jsonl
```

### 2. Processing a Gzipped CSV database dump
```bash
datum-mask \
  --input customers.csv.gz \
  --output sanitized-customers.csv.gz \
  --gzip \
  --format csv \
  --secret "team-audit-key" \
  --rules "email:email,phone:phone,ssn:redact"
```

### 3. Autodetect PII across arbitrarily nested JSON records
```bash
datum-mask --auto-detect < raw-logs.jsonl > masked-logs.jsonl
```

## Running Tests

Run the integrated smoke test suite:
```bash
npm test
```


---

## 📄 License
MIT License.
