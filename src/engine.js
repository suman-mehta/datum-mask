import crypto from 'node:crypto';

export class MaskEngine {
  constructor(secretKey = 'datum-mask-default-secret') {
    this.secretKey = Buffer.isBuffer(secretKey) ? secretKey : Buffer.from(String(secretKey), 'utf8');
  }

  deriveHash(val, salt = 'generic') {
    return crypto.createHmac('sha256', this.secretKey)
      .update(salt)
      .update(String(val))
      .digest();
  }

  maskString(val, salt = 'str') {
    if (val === null || val === undefined) return val;
    const str = String(val);
    if (str.length === 0) return '';
    const hash = this.deriveHash(str, salt).toString('hex');
    let out = '';
    for (let i = 0; i < str.length; i++) {
      const ch = str[i];
      const hexChar = hash[i % hash.length];
      const code = parseInt(hexChar, 16);
      if (/[a-z]/.test(ch)) {
        out += String.fromCharCode(97 + (code % 26));
      } else if (/[A-Z]/.test(ch)) {
        out += String.fromCharCode(65 + (code % 26));
      } else if (/[0-9]/.test(ch)) {
        out += String.fromCharCode(48 + (code % 10));
      } else {
        out += ch;
      }
    }
    return out;
  }

  maskEmail(val) {
    if (!val || typeof val !== 'string' || !val.includes('@')) return this.maskString(val, 'email');
    const [user, domain] = val.split('@');
    const uHash = this.deriveHash(user, 'email_user').toString('hex').slice(0, 8);
    const domainParts = domain.split('.');
    const tld = domainParts.length > 1 ? domainParts.pop() : 'internal';
    const dHash = this.deriveHash(domainParts.join('.'), 'email_domain').toString('hex').slice(0, 6);
    return `${uHash}@${dHash}.${tld}`;
  }

  maskIpv4(val) {
    if (!val || typeof val !== 'string') return val;
    const hash = this.deriveHash(val, 'ipv4');
    // Map deterministically into 10.x.x.x private space
    return `10.${hash[0]}.${hash[1]}.${hash[2]}`;
  }

  maskUuid(val) {
    if (!val || typeof val !== 'string') return val;
    const h = this.deriveHash(val, 'uuid').toString('hex');
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`;
  }

  maskPhone(val) {
    if (!val || typeof val !== 'string') return val;
    const digits = val.replace(/\D/g, '');
    if (digits.length < 4) return this.maskString(val, 'phone');
    const hash = this.deriveHash(digits, 'phone').toString('hex');
    let digitIdx = 0;
    let out = '';
    for (let i = 0; i < val.length; i++) {
      if (/\d/.test(val[i])) {
        const nibble = parseInt(hash[digitIdx % hash.length], 16);
        out += String(nibble % 10);
        digitIdx++;
      } else {
        out += val[i];
      }
    }
    return out;
  }

  maskValueByRule(val, rule) {
    if (val === null || val === undefined) return val;
    switch (rule) {
      case 'email': return this.maskEmail(String(val));
      case 'ip':
      case 'ipv4': return this.maskIpv4(String(val));
      case 'uuid': return this.maskUuid(String(val));
      case 'phone': return this.maskPhone(String(val));
      case 'redact': return '[REDACTED]';
      case 'string':
      default:
        return this.maskString(String(val), rule);
    }
  }

  detectAndMask(val) {
    if (typeof val !== 'string') return val;
    if (/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(val)) {
      return this.maskEmail(val);
    }
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(val)) {
      return this.maskIpv4(val);
    }
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(val)) {
      return this.maskUuid(val);
    }
    if (/^\+?[0-9\s\-\(\)]{10,20}$/.test(val) && (val.match(/\d/g) || []).length >= 10) {
      return this.maskPhone(val);
    }
    return val;
  }
}
