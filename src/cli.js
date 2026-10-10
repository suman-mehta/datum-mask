#!/usr/bin/env node

import fs from 'node:fs';
import zlib from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import { MaskEngine } from './engine.js';
import { JsonlMaskTransform, CsvMaskTransform } from './transformer.js';

function printHelp() {
  const help = `
datum-mask: Deterministic Dataset PII Scrubber

Usage:
  datum-mask [options]

Options:
  --secret, -s <key>       Deterministic HMAC master secret (default: env DATUM_SECRET or builtin default)
  --format, -f <fmt>       Input format: 'jsonl' (default) or 'csv'
  --rules, -r <spec>       Field rules specification (e.g. "email:email,user_id:uuid,ip_address:ip")
  --auto-detect, -a        Autodetect email, ipv4, uuid, phone strings in JSON unmapped fields
  --input, -i <path>       Input file path (default: stdin)
  --output, -o <path>      Output file path (default: stdout)
  --gzip                   Process input/output through transparent gzip decompression/compression
  --help, -h               Show this help message

Rules syntax:
  fieldName:ruleType where ruleType in [email, ip, ipv4, uuid, phone, redact, string]

Examples:
  cat users.jsonl | datum-mask --rules "email:email,id:uuid" > scrubbed.jsonl
  datum-mask -i raw.csv -o clean.csv -f csv --rules "customer_email:email,phone_num:phone"
`;
  process.stdout.write(help);
}

function parseArgs(args) {
  const opts = {
    secret: process.env.DATUM_SECRET || 'datum-default-secret-seed',
    format: 'jsonl',
    rules: {},
    autoDetect: false,
    input: null,
    output: null,
    gzip: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    } else if (arg === '--secret' || arg === '-s') {
      opts.secret = args[++i];
    } else if (arg === '--format' || arg === '-f') {
      opts.format = args[++i].toLowerCase();
    } else if (arg === '--auto-detect' || arg === '-a') {
      opts.autoDetect = true;
    } else if (arg === '--input' || arg === '-i') {
      opts.input = args[++i];
    } else if (arg === '--output' || arg === '-o') {
      opts.output = args[++i];
    } else if (arg === '--gzip') {
      opts.gzip = true;
    } else if (arg === '--rules' || arg === '-r') {
      const rawRules = args[++i] || '';
      for (const pair of rawRules.split(',')) {
        const [field, rule] = pair.split(':').map(s => s.trim());
        if (field && rule) {
          opts.rules[field] = rule;
        }
      }
    }
  }
  return opts;
}

async function main() {
  const args = process.argv.slice(2);
  const opts = parseArgs(args);

  const engine = new MaskEngine(opts.secret);
  let inputStream = opts.input ? fs.createReadStream(opts.input) : process.stdin;
  let outputStream = opts.output ? fs.createWriteStream(opts.output) : process.stdout;

  const streams = [];

  if (opts.gzip) {
    streams.push(inputStream);
    streams.push(zlib.createGunzip());
  } else {
    streams.push(inputStream);
  }

  if (opts.format === 'csv') {
    streams.push(new CsvMaskTransform(engine, opts.rules));
  } else {
    streams.push(new JsonlMaskTransform(engine, opts.rules, opts.autoDetect));
  }

  if (opts.gzip) {
    streams.push(zlib.createGzip());
  }
  streams.push(outputStream);

  try {
    await pipeline(...streams);
  } catch (err) {
    process.stderr.write(`datum-mask error: ${err.message}\n`);
    process.exit(1);
  }
}

main();
