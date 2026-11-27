(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.Veil = root.Veil || {};
    root.Veil.Sample = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const SAMPLE_TEXT = [
    '# SYNTHETIC TEST DATA ONLY — NO REAL PII',
    'Incident Date: 2026-11-27',
    'Order Reference: ORD-2026-88412',
    'App Version: v2.4.1.8',
    '',
    'Primary Contact: ananya.sharma@example.org',
    'Escalation CC: Ananya.Sharma@example.org',
    'Security Alias: sec.ops@veil-demo.test',
    '',
    'Mobile (formatted): +91 98765-43210',
    'Mobile (plain): 9876543210',
    'Mobile (alt): +91 91234 56789',
    '',
    'Source IPv4 (valid): 192.168.1.10',
    'Gateway IPv4 (valid): 10.0.42.7',
    'Malformed IPv4 (must ignore): 999.12.4.1',
    '',
    'PAN Identifier: ABCDE1234F',
    'Aadhaar-shaped ID: 2345 6789 0123',
    '',
    'Test Card 1 (Luhn valid): 4111 1111 1111 1111',
    'Test Card 2 (Luhn valid): 5555 5555 5555 4444',
    'Invalid Card (Luhn fail, must ignore): 4111 1111 1111 1112'
  ].join('\n');

  const PROMPT_LOG = Object.freeze([
    {
      step: 1,
      prompt: 'Create a privacy-first PII detection engine with zero network calls or storage.'
    },
    {
      step: 2,
      prompt: 'Implement Luhn validation for credit card candidates and Verhoeff indicator for Aadhaar-shaped IDs.'
    },
    {
      step: 3,
      prompt: 'Resolve overlapping detections deterministically by entity priority and span length.'
    },
    {
      step: 4,
      prompt: 'Add Full Mask, Partial Mask, and in-memory consistent pseudonymization modes.'
    },
    {
      step: 5,
      prompt: 'Build the mocha brown, platinum silver, and pale lavender UI with live scan animations and safe textContent diff highlighting.'
    },
    {
      step: 6,
      prompt: 'Add local .txt/.csv file upload, sanitized Blob export, Clipboard copy, and live audit summary.'
    }
  ]);

  return {
    SAMPLE_TEXT: SAMPLE_TEXT,
    PROMPT_LOG: PROMPT_LOG
  };
});
