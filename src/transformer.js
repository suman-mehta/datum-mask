import { Transform } from 'node:stream';

export class JsonlMaskTransform extends Transform {
  constructor(engine, fieldRules = {}, autoDetect = false) {
    super({ objectMode: false });
    this.engine = engine;
    this.fieldRules = fieldRules;
    this.autoDetect = autoDetect;
    this.buffer = '';
  }

  _transform(chunk, encoding, callback) {
    this.buffer += chunk.toString('utf8');
    const lines = this.buffer.split('\n');
    this.buffer = lines.pop();

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) {
        this.push('\n');
        continue;
      }
      try {
        const parsed = JSON.parse(trimmed);
        const masked = this._maskObject(parsed);
        this.push(JSON.stringify(masked) + '\n');
      } catch {
        this.push(line + '\n');
      }
    }
    callback();
  }

  _flush(callback) {
    if (this.buffer.trim()) {
      try {
        const parsed = JSON.parse(this.buffer.trim());
        const masked = this._maskObject(parsed);
        this.push(JSON.stringify(masked) + '\n');
      } catch {
        this.push(this.buffer + '\n');
      }
    }
    callback();
  }

  _maskObject(obj, prefix = '') {
    if (obj === null || typeof obj !== 'object') return obj;
    if (Array.isArray(obj)) {
      return obj.map(item => this._maskObject(item, prefix));
    }

    const result = {};
    for (const [key, val] of Object.entries(obj)) {
      const path = prefix ? `${prefix}.${key}` : key;
      const explicitRule = this.fieldRules[path] || this.fieldRules[key];

      if (explicitRule) {
        result[key] = this.engine.maskValueByRule(val, explicitRule);
      } else if (val !== null && typeof val === 'object') {
        result[key] = this._maskObject(val, path);
      } else if (this.autoDetect && typeof val === 'string') {
        result[key] = this.engine.detectAndMask(val);
      } else {
        result[key] = val;
      }
    }
    return result;
  }
}

export class CsvMaskTransform extends Transform {
  constructor(engine, fieldRules = {}, delimiter = ',') {
    super({ objectMode: false });
    this.engine = engine;
    this.fieldRules = fieldRules;
    this.delimiter = delimiter;
    this.headers = null;
    this.buffer = '';
  }

  _transform(chunk, encoding, callback) {
    this.buffer += chunk.toString('utf8');
    const lines = this.buffer.split(/\r?\n/);
    this.buffer = lines.pop();

    for (const line of lines) {
      if (!line) continue;
      const cols = this._parseCsvLine(line);
      if (!this.headers) {
        this.headers = cols.map(c => c.trim());
        this.push(cols.join(this.delimiter) + '\n');
        continue;
      }

      const maskedCols = cols.map((col, idx) => {
        const header = this.headers[idx];
        const rule = this.fieldRules[header];
        if (rule) {
          return this.engine.maskValueByRule(col, rule);
        }
        return col;
      });
      this.push(maskedCols.join(this.delimiter) + '\n');
    }
    callback();
  }

  _flush(callback) {
    if (this.buffer.trim() && this.headers) {
      const cols = this._parseCsvLine(this.buffer.trim());
      const maskedCols = cols.map((col, idx) => {
        const header = this.headers[idx];
        const rule = this.fieldRules[header];
        return rule ? this.engine.maskValueByRule(col, rule) : col;
      });
      this.push(maskedCols.join(this.delimiter) + '\n');
    }
    callback();
  }

  _parseCsvLine(line) {
    return line.split(this.delimiter);
  }
}
