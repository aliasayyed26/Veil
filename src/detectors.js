(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.Veil = root.Veil || {};
    root.Veil.Detectors = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const TYPE_PRIORITY = Object.freeze({
    card: 6,
    email: 5,
    aadhaar: 4,
    pan: 3,
    ipv4: 2,
    phone: 1
  });

  // Verhoeff dihedral multiplication, permutation, and inverse tables
  const VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
  ];

  const VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
  ];

  /**
   * Validates a 12+ digit string using the Verhoeff checksum algorithm.
   */
  function validateVerhoeff(numberString) {
    const digits = String(numberString).replace(/\D/g, '');
    if (!digits) return false;
    let c = 0;
    for (let i = 0; i < digits.length; i++) {
      const digit = digits.charCodeAt(digits.length - 1 - i) - 48;
      if (digit < 0 || digit > 9) return false;
      c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]];
    }
    return c === 0;
  }

  /**
   * Validates a candidate credit card number using the Luhn algorithm.
   */
  function validateLuhn(numberString) {
    const digits = String(numberString).replace(/[\s-]/g, '');
    if (!/^\d{13,19}$/.test(digits)) return false;

    let sum = 0;
    let shouldDouble = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let digit = digits.charCodeAt(i) - 48;
      if (shouldDouble) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      sum += digit;
      shouldDouble = !shouldDouble;
    }
    return sum % 10 === 0;
  }

  /**
   * Detects RFC-style email addresses (case-insensitive).
   */
  function detectEmails(text) {
    if (!text) return [];
    const spans = [];
    const regex = /(?<![A-Za-z0-9._%+-])([A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,62}[A-Za-z0-9])?@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})(?![A-Za-z0-9._%+-])/gi;
    let match;
    while ((match = regex.exec(text)) !== null) {
      const value = match[1];
      const [local, domain] = value.split('@');
      if (local.includes('..') || domain.includes('..')) continue;
      spans.push({
        type: 'email',
        start: match.index,
        end: match.index + value.length,
        value,
        note: 'RFC-style email pattern'
      });
    }
    return spans;
  }

  /**
   * Detects Indian mobile numbers (optional +91/91 prefix, 10 digits starting 6-9).
   */
  function detectPhoneNumbers(text) {
    if (!text) return [];
    const spans = [];
    const regex = /(?<![\dA-Za-z.])(?<!\d-)(?:\+?91[ \t-]?)?(?:[6-9]\d{9}|[6-9]\d{4}[ \t-]\d{5}|[6-9]\d{3}[ \t-]\d{3}[ \t-]\d{3}|[6-9]\d{2}[ \t-]\d{3}[ \t-]\d{4})(?![\dA-Za-z.])(?!-\d)/g;
    let match;
    while ((match = regex.exec(text)) !== null) {
      const value = match[0];
      spans.push({
        type: 'phone',
        start: match.index,
        end: match.index + value.length,
        value,
        note: 'Indian mobile format'
      });
    }
    return spans;
  }

  /**
   * Detects IPv4 addresses with octets validated in 0-255, rejecting longer dotted sequences.
   */
  function detectIPv4(text) {
    if (!text) return [];
    const spans = [];
    const regex = /(?<![\d.A-Za-z])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.A-Za-z])/g;
    let match;
    while ((match = regex.exec(text)) !== null) {
      const value = match[1];
      const octets = value.split('.');
      const valid = octets.length === 4 && octets.every(function (octet) {
        if (octet.length > 1 && octet.startsWith('0')) return false;
        const n = Number(octet);
        return Number.isInteger(n) && n >= 0 && n <= 255;
      });
      if (!valid) continue;
      spans.push({
        type: 'ipv4',
        start: match.index,
        end: match.index + value.length,
        value,
        note: 'Valid IPv4 (0-255 octets)'
      });
    }
    return spans;
  }

  /**
   * Detects Indian PAN identifiers ([A-Z]{5}[0-9]{4}[A-Z]) on word boundaries.
   */
  function detectPAN(text) {
    if (!text) return [];
    const spans = [];
    const regex = /\b([A-Z]{5}[0-9]{4}[A-Z])\b/g;
    let match;
    while ((match = regex.exec(text)) !== null) {
      const value = match[1];
      spans.push({
        type: 'pan',
        start: match.index,
        end: match.index + value.length,
        value,
        note: 'PAN format [A-Z]{5}[0-9]{4}[A-Z]'
      });
    }
    return spans;
  }

  /**
   * Detects 12-digit Aadhaar-shaped numbers starting 2-9 (shape-only, with Verhoeff indicator).
   */
  function detectAadhaar(text) {
    if (!text) return [];
    const spans = [];
    const regex = /(?<![\dA-Za-z.])(?<!\d[ \t-])([2-9]\d{3}(?:[ \t-]?\d{4}){2})(?![\dA-Za-z.])(?![ \t-]\d)/g;
    let match;
    while ((match = regex.exec(text)) !== null) {
      const value = match[1];
      const digits = value.replace(/\D/g, '');
      if (digits.length !== 12) continue;
      const checksumOk = validateVerhoeff(digits);
      spans.push({
        type: 'aadhaar',
        start: match.index,
        end: match.index + value.length,
        value,
        note: checksumOk
          ? 'shape only, no checksum required (Verhoeff checksum valid)'
          : 'shape only, no checksum'
      });
    }
    return spans;
  }

  /**
   * Detects 13-19 digit credit card numbers passing Luhn validation.
   */
  function detectCreditCards(text) {
    if (!text) return [];
    const spans = [];
    const regex = /(?<![\dA-Za-z.])(?<!\d[ \t-])(\d{13,19}|\d{4}(?:[ \t-]\d{4,6}){1,3}[ \t-]\d{2,6}|\d{4}(?:[ \t-]\d{3}){3})(?![\dA-Za-z.])(?![ \t-]\d)/g;
    let match;
    while ((match = regex.exec(text)) !== null) {
      const value = match[1];
      if (/^[0\s-]+$/.test(value)) continue;
      if (!validateLuhn(value)) continue;
      spans.push({
        type: 'card',
        start: match.index,
        end: match.index + value.length,
        value,
        note: 'Luhn valid'
      });
    }
    return spans;
  }

  /**
   * Binary-search overlap check against kept spans sorted by start index.
   */
  function hasOverlap(sortedKept, candidate) {
    let lo = 0;
    let hi = sortedKept.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const span = sortedKept[mid];
      if (candidate.end <= span.start) {
        hi = mid - 1;
      } else if (candidate.start >= span.end) {
        lo = mid + 1;
      } else {
        return true;
      }
    }
    return false;
  }

  /**
   * Inserts a non-overlapping span into sortedKept while maintaining start-index order.
   */
  function insertSorted(sortedKept, span) {
    let lo = 0;
    let hi = sortedKept.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (sortedKept[mid].start < span.start) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    sortedKept.splice(lo, 0, span);
  }

  /**
   * Runs all detectors, resolves overlaps by priority and span length, and returns spans sorted by start index.
   */
  function classifyEntities(text) {
    if (typeof text !== 'string' || text.length === 0) {
      return [];
    }

    const candidates = [].concat(
      detectCreditCards(text),
      detectEmails(text),
      detectAadhaar(text),
      detectPAN(text),
      detectIPv4(text),
      detectPhoneNumbers(text)
    );

    candidates.sort(function (a, b) {
      const priorityDiff = (TYPE_PRIORITY[b.type] || 0) - (TYPE_PRIORITY[a.type] || 0);
      if (priorityDiff !== 0) return priorityDiff;
      const lenDiff = (b.end - b.start) - (a.end - a.start);
      if (lenDiff !== 0) return lenDiff;
      return a.start - b.start;
    });

    const kept = [];
    for (let i = 0; i < candidates.length; i++) {
      const candidate = candidates[i];
      if (!hasOverlap(kept, candidate)) {
        insertSorted(kept, candidate);
      }
    }
    return kept;
  }

  return {
    TYPE_PRIORITY: TYPE_PRIORITY,
    validateLuhn: validateLuhn,
    validateVerhoeff: validateVerhoeff,
    detectEmails: detectEmails,
    detectPhoneNumbers: detectPhoneNumbers,
    detectIPv4: detectIPv4,
    detectPAN: detectPAN,
    detectAadhaar: detectAadhaar,
    detectCreditCards: detectCreditCards,
    classifyEntities: classifyEntities
  };
});
