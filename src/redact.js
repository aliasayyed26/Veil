(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.Veil = root.Veil || {};
    root.Veil.Redact = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const PSEUDONYM_PREFIX = Object.freeze({
    email: 'USER',
    phone: 'PHONE',
    ipv4: 'IP',
    pan: 'PAN',
    aadhaar: 'AADHAAR',
    card: 'CARD'
  });

  const MODES = Object.freeze({
    FULL: 'full',
    PARTIAL: 'partial',
    PSEUDONYM: 'pseudonym'
  });

  /**
   * Normalizes an entity value for consistent pseudonym keying within a single document run.
   */
  function normalizeEntityValue(type, value) {
    const raw = String(value || '').trim();
    switch (type) {
      case 'email':
        return raw.toLowerCase();
      case 'phone': {
        const digits = raw.replace(/\D/g, '');
        if (digits.length === 12 && digits.startsWith('91')) {
          return digits.slice(2);
        }
        return digits;
      }
      case 'pan':
        return raw.toUpperCase();
      case 'ipv4':
        return raw
          .split('.')
          .map(function (octet) {
            return String(Number(octet));
          })
          .join('.');
      case 'aadhaar':
      case 'card':
        return raw.replace(/\D/g, '');
      default:
        return raw;
    }
  }

  /**
   * Full redaction: replaces every detected entity with [REDACTED].
   */
  function redactFull() {
    return '[REDACTED]';
  }

  /**
   * Partial redaction: preserves minimal non-sensitive shape/suffix per entity type.
   */
  function redactPartial(span) {
    const type = span.type;
    const value = String(span.value || '');

    switch (type) {
      case 'email': {
        const atIdx = value.indexOf('@');
        if (atIdx <= 0) return '[REDACTED]';
        const local = value.slice(0, atIdx);
        const domain = value.slice(atIdx + 1);
        const lastDot = domain.lastIndexOf('.');
        const localMasked = local.charAt(0) + '***';
        if (lastDot <= 0) {
          return localMasked + '@' + domain.charAt(0) + '***';
        }
        const tld = domain.slice(lastDot);
        return localMasked + '@' + domain.charAt(0) + '***' + tld;
      }
      case 'phone': {
        const digits = value.replace(/\D/g, '');
        const last4 = digits.slice(-4);
        return 'XXXXXX' + last4;
      }
      case 'pan': {
        if (value.length !== 10) return 'XXXXXXXXXX';
        return 'XXXXX' + value.slice(5, 9) + 'X';
      }
      case 'card': {
        const digits = value.replace(/\D/g, '');
        const last4 = digits.slice(-4);
        return 'XXXX-XXXX-XXXX-' + last4;
      }
      case 'ipv4':
        return 'XXX.XXX.XXX.XXX';
      case 'aadhaar': {
        const digits = value.replace(/\D/g, '');
        const last4 = digits.slice(-4);
        return 'XXXX XXXX ' + last4;
      }
      default:
        return '[REDACTED]';
    }
  }

  /**
   * Generates consistent per-document pseudonyms in memory only for a single run.
   * Accepts either an array of spans (returns aligned array of placeholders) or (span, state).
   */
  function pseudonymize(spansOrSpan, existingState) {
    if (Array.isArray(spansOrSpan)) {
      const state = {
        mappings: new Map(),
        counters: Object.create(null)
      };
      const results = spansOrSpan.map(function (span) {
        return pseudonymize(span, state);
      });
      state.mappings.clear();
      return results;
    }

    const span = spansOrSpan;
    const state = existingState || {
      mappings: new Map(),
      counters: Object.create(null)
    };
    const prefix = PSEUDONYM_PREFIX[span.type] || 'ENTITY';
    const normalized = normalizeEntityValue(span.type, span.value);
    const key = span.type + ':' + normalized;

    if (state.mappings.has(key)) {
      return state.mappings.get(key);
    }

    const nextCount = (state.counters[span.type] || 0) + 1;
    state.counters[span.type] = nextCount;
    const placeholder = prefix + '_' + String(nextCount).padStart(2, '0');
    state.mappings.set(key, placeholder);
    return placeholder;
  }

  /**
   * Applies the selected redaction mode by slicing original text between classified spans.
   * Rebuilds pseudonym mappings in memory on each call and discards them before returning.
   */
  function applyRedaction(text, spans, mode) {
    const source = typeof text === 'string' ? text : '';
    const orderedSpans = Array.isArray(spans) ? spans : [];
    const activeMode = mode === MODES.PARTIAL || mode === MODES.PSEUDONYM ? mode : MODES.FULL;

    const pseudonymState = activeMode === MODES.PSEUDONYM
      ? { mappings: new Map(), counters: Object.create(null) }
      : null;

    const chunks = [];
    const replacements = [];
    let cursor = 0;
    let outLength = 0;

    for (let i = 0; i < orderedSpans.length; i++) {
      const span = orderedSpans[i];
      if (span.start < cursor || span.end > source.length || span.start > span.end) {
        continue;
      }

      if (span.start > cursor) {
        const unchanged = source.slice(cursor, span.start);
        chunks.push(unchanged);
        outLength += unchanged.length;
      }

      let replacement;
      if (activeMode === MODES.PARTIAL) {
        replacement = redactPartial(span);
      } else if (activeMode === MODES.PSEUDONYM) {
        replacement = pseudonymize(span, pseudonymState);
      } else {
        replacement = redactFull(span);
      }

      const outStart = outLength;
      chunks.push(replacement);
      outLength += replacement.length;

      replacements.push({
        type: span.type,
        start: outStart,
        end: outLength,
        replacement: replacement,
        note: span.note
      });

      cursor = span.end;
    }

    if (cursor < source.length) {
      chunks.push(source.slice(cursor));
    }

    if (pseudonymState) {
      pseudonymState.mappings.clear();
    }

    return {
      sanitizedText: chunks.join(''),
      mode: activeMode,
      replacements: replacements
    };
  }

  return {
    MODES: MODES,
    PSEUDONYM_PREFIX: PSEUDONYM_PREFIX,
    normalizeEntityValue: normalizeEntityValue,
    redactFull: redactFull,
    redactPartial: redactPartial,
    pseudonymize: pseudonymize,
    applyRedaction: applyRedaction
  };
});
