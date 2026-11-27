(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.Veil = root.Veil || {};
    root.Veil.Export = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  /**
   * Builds a sanitized filename while keeping only safe characters.
   */
  function buildSanitizedFilename(originalName, extension) {
    const ext = extension === 'csv' ? 'csv' : 'txt';
    if (!originalName || typeof originalName !== 'string') {
      return 'veil-sanitized.' + ext;
    }
    const base = originalName
      .replace(/\.[^.]+$/, '')
      .replace(/[^A-Za-z0-9_-]+/g, '-')
      .replace(/^-+|-+$/g, '');
    return (base || 'veil-document') + '-sanitized.' + ext;
  }

  /**
   * Downloads ONLY the sanitized text as a .txt or .csv file using the Blob API and revokes the Object URL.
   */
  function downloadSanitizedFile(sanitizedText, options) {
    if (typeof sanitizedText !== 'string' || sanitizedText.length === 0) {
      return {
        ok: false,
        reason: 'empty',
        message: 'Nothing to download yet. Enter text or load a file first.'
      };
    }

    const opts = options || {};
    const format = opts.format === 'csv' ? 'csv' : 'txt';
    const mimeType = format === 'csv'
      ? 'text/csv;charset=utf-8'
      : 'text/plain;charset=utf-8';
    const filename = buildSanitizedFilename(opts.originalName, format);

    const blob = new Blob([sanitizedText], { type: mimeType });
    const url = URL.createObjectURL(blob);

    try {
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filename;
      anchor.style.display = 'none';
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
    } finally {
      setTimeout(function () {
        URL.revokeObjectURL(url);
      }, 1000);
    }

    return {
      ok: true,
      filename: filename,
      format: format,
      message: 'Downloaded sanitized ' + format.toUpperCase() + ' (' + filename + ').'
    };
  }

  /**
   * Copies ONLY the sanitized text to the clipboard using the Clipboard API.
   */
  async function copy(sanitizedText) {
    if (typeof sanitizedText !== 'string' || sanitizedText.length === 0) {
      return {
        ok: false,
        reason: 'empty',
        message: 'Nothing to copy yet. Enter text or load a file first.'
      };
    }

    if (typeof navigator !== 'undefined' && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      try {
        await navigator.clipboard.writeText(sanitizedText);
        return {
          ok: true,
          message: 'Sanitized text copied to clipboard.'
        };
      } catch (_err) {
        // Fall through to execCommand fallback for restricted file:// contexts
      }
    }

    if (typeof document !== 'undefined') {
      const temp = document.createElement('textarea');
      temp.value = sanitizedText;
      temp.setAttribute('readonly', '');
      temp.style.position = 'fixed';
      temp.style.opacity = '0';
      temp.style.pointerEvents = 'none';
      document.body.appendChild(temp);
      temp.select();
      let copied = false;
      try {
        copied = document.execCommand('copy');
      } finally {
        document.body.removeChild(temp);
      }
      if (copied) {
        return {
          ok: true,
          message: 'Sanitized text copied to clipboard.'
        };
      }
    }

    return {
      ok: false,
      reason: 'unsupported',
      message: 'Clipboard access was blocked by the browser. Use Download instead.'
    };
  }

  /**
   * Validates an uploaded File object to accept only .txt and .csv files.
   */
  function validateUploadFile(file) {
    if (!file || typeof file.name !== 'string') {
      return { ok: false, message: 'No file selected.' };
    }
    const lower = file.name.toLowerCase();
    if (lower.endsWith('.txt')) {
      return { ok: true, fileType: 'TXT', format: 'txt' };
    }
    if (lower.endsWith('.csv')) {
      return { ok: true, fileType: 'CSV', format: 'csv' };
    }
    return {
      ok: false,
      message: 'Unsupported file type. Only .txt and .csv files are accepted.'
    };
  }

  return {
    buildSanitizedFilename: buildSanitizedFilename,
    downloadSanitizedFile: downloadSanitizedFile,
    copy: copy,
    validateUploadFile: validateUploadFile
  };
});
