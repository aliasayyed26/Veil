(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.Veil = root.Veil || {};
    root.Veil.Audit = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const MODE_LABELS = Object.freeze({
    full: 'Full Mask',
    partial: 'Partial Mask',
    pseudonym: 'Pseudonymize'
  });

  /**
   * Generates a privacy-safe audit summary containing only counts and metadata (never raw text or mappings).
   */
  function generateAuditSummary(options) {
    const opts = options || {};
    const spans = Array.isArray(opts.spans) ? opts.spans : [];
    const replacements = Array.isArray(opts.replacements) ? opts.replacements : [];
    const mode = opts.mode || 'full';
    const fileType = opts.fileType || 'None';
    const status = opts.status || 'Idle';

    const counts = {
      email: 0,
      phone: 0,
      ipv4: 0,
      pan: 0,
      aadhaar: 0,
      card: 0
    };

    for (let i = 0; i < spans.length; i++) {
      const t = spans[i].type;
      if (Object.prototype.hasOwnProperty.call(counts, t)) {
        counts[t] += 1;
      }
    }

    return {
      counts: counts,
      totalDetected: spans.length,
      entitiesRedacted: replacements.length,
      selectedMode: MODE_LABELS[mode] || 'Full Mask',
      modeKey: mode,
      fileType: fileType,
      status: status
    };
  }

  return {
    MODE_LABELS: MODE_LABELS,
    generateAuditSummary: generateAuditSummary
  };
});
