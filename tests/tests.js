(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    const Detectors = require('../src/detectors.js');
    const Redact = require('../src/redact.js');
    const Audit = require('../src/audit.js');
    const Export = require('../src/export.js');
    const Sample = require('../src/sample.js');
    const runner = factory(Detectors, Redact, Audit, Export, Sample, true);
    if (require.main === module) {
      runner.runAllTestsAsync().then(function (summary) {
        summary.results.forEach(function (item) {
          const prefix = item.pass ? '[PASS]' : '[FAIL]';
          process.stdout.write(prefix + ' ' + item.name + (item.error ? ' -> ' + item.error : '') + '\n');
        });
        process.stdout.write('\nTotal: ' + summary.passed + '/' + summary.total + ' passed.\n');
        if (summary.failed > 0) {
          process.exitCode = 1;
        }
      });
    }
    module.exports = runner;
  } else {
    root.VeilTests = factory(
      root.Veil.Detectors,
      root.Veil.Redact,
      root.Veil.Audit,
      root.Veil.Export,
      root.Veil.Sample,
      false
    );
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function (Detectors, Redact, Audit, Export, Sample, isNode) {
  'use strict';

  function assert(condition, message) {
    if (!condition) {
      throw new Error(message || 'Assertion failed');
    }
  }

  function assertEqual(actual, expected, message) {
    if (actual !== expected) {
      throw new Error((message ? message + ': ' : '') + 'expected ' + JSON.stringify(expected) + ', got ' + JSON.stringify(actual));
    }
  }

  function buildTestCases() {
    const cases = [];

    function test(name, fn) {
      cases.push({ name: name, fn: fn });
    }

    test('Valid and invalid emails', function () {
      const text = 'Valid: alice.bob+1@Example.COM, a@b.io | Invalid: @nope.com, user@.com, user@domain, user..name@test.com';
      const spans = Detectors.detectEmails(text);
      assertEqual(spans.length, 2, 'Expected exactly 2 valid emails');
      assertEqual(spans[0].value, 'alice.bob+1@Example.COM');
      assertEqual(spans[1].value, 'a@b.io');
    });

    test('Valid and invalid Indian phone formats', function () {
      const text = [
        'Valid: +91 98765-43210, 9876543210, 91-91234-56789, 99887 76655',
        'Invalid: 5123456789, 123456789012, 987654321, ORD9876543210, 2026-9876543210'
      ].join('\n');
      const spans = Detectors.detectPhoneNumbers(text);
      assertEqual(spans.length, 4, 'Expected 4 valid Indian mobile numbers');
      assertEqual(spans[0].value, '+91 98765-43210');
      assertEqual(spans[1].value, '9876543210');
      assertEqual(spans[2].value, '91-91234-56789');
      assertEqual(spans[3].value, '99887 76655');
    });

    test('Valid IPv4 detected and invalid IPv4 / version strings rejected', function () {
      const text = 'Hosts: 192.168.1.10 and 0.0.0.0 | Reject: 999.12.4.1, 256.1.1.1, 1.2.3.4.5, v1.2.3.4, 192.168.01.1';
      const spans = Detectors.detectIPv4(text);
      assertEqual(spans.length, 2, 'Expected 2 valid IPv4 addresses');
      assertEqual(spans[0].value, '192.168.1.10');
      assertEqual(spans[1].value, '0.0.0.0');
    });

    test('PAN detected and invalid shapes rejected', function () {
      const text = 'Valid: ABCDE1234F | Invalid: abcde1234f, ABCD1234F, ABCDE12345, ABCDE1234FX';
      const spans = Detectors.detectPAN(text);
      assertEqual(spans.length, 1, 'Expected 1 valid PAN');
      assertEqual(spans[0].value, 'ABCDE1234F');
    });

    test('Aadhaar-shaped 2345 6789 0123 detected and invalid starting digit rejected', function () {
      const text = 'Valid: 2345 6789 0123 and 3456-7890-1234 | Reject: 1234 5678 9012, 0123 4567 8901';
      const spans = Detectors.detectAadhaar(text);
      assertEqual(spans.length, 2, 'Expected 2 Aadhaar-shaped matches');
      assertEqual(spans[0].value, '2345 6789 0123');
      assert(spans[0].note.includes('shape only'), 'Expected shape-only note');
      assertEqual(spans[1].value, '3456-7890-1234');
    });

    test('Luhn-valid cards detected and Luhn-failing number rejected', function () {
      assert(Detectors.validateLuhn('4111 1111 1111 1111'), 'Visa 4111...1111 should pass Luhn');
      assert(Detectors.validateLuhn('5555-5555-5555-4444'), 'MC 5555...4444 should pass Luhn');
      assert(!Detectors.validateLuhn('4111 1111 1111 1112'), '4111...1112 must fail Luhn');

      const text = 'Valid: 4111 1111 1111 1111, 5555 5555 5555 4444 | Invalid: 4111 1111 1111 1112, 5555 5555 5555 4445';
      const spans = Detectors.classifyEntities(text);
      assertEqual(spans.length, 2, 'Only Luhn-valid cards should be classified');
      assertEqual(spans[0].type, 'card');
      assertEqual(spans[1].type, 'card');
    });

    test('Overlap priority prevents cards from double-counting as Aadhaar or phone', function () {
      const text = 'Card: 4111 1111 1111 1111 and 5555555555554444';
      const spans = Detectors.classifyEntities(text);
      assertEqual(spans.length, 2);
      assertEqual(spans[0].type, 'card');
      assertEqual(spans[1].type, 'card');
    });

    test('Dates, order IDs, and ordinary numbers are not flagged', function () {
      const text = 'Date: 2026-11-27, Order: ORD-2026-88412, Invoice: INV-99402, Amount: 45210, Zip: 560001';
      const spans = Detectors.classifyEntities(text);
      assertEqual(spans.length, 0, 'Expected zero false positives');
    });

    test('Repeated emails and normalized phone variants receive consistent pseudonyms', function () {
      const text = [
        'First: Alice@Example.com',
        'Second: alice@example.com',
        'Phone A: +91 98765-43210',
        'Phone B: 9876543210',
        'Other Email: bob@example.org'
      ].join('\n');
      const spans = Detectors.classifyEntities(text);
      const res = Redact.applyRedaction(text, spans, 'pseudonym');
      const lines = res.sanitizedText.split('\n');
      assertEqual(lines[0], 'First: USER_01');
      assertEqual(lines[1], 'Second: USER_01');
      assertEqual(lines[2], 'Phone A: PHONE_01');
      assertEqual(lines[3], 'Phone B: PHONE_01');
      assertEqual(lines[4], 'Other Email: USER_02');
    });

    test('All three redaction modes preserve surrounding text and line breaks exactly', function () {
      const text = '  Lead:\n\tEmail=rahul@gmail.com | Phone=+91 98765-43210\r\n\tPAN=ABCDE1234F | Card=4111 1111 1111 1111 | IP=192.168.1.10 | UID=2345 6789 0123  ';
      const spans = Detectors.classifyEntities(text);

      const full = Redact.applyRedaction(text, spans, 'full');
      assertEqual(
        full.sanitizedText,
        '  Lead:\n\tEmail=[REDACTED] | Phone=[REDACTED]\r\n\tPAN=[REDACTED] | Card=[REDACTED] | IP=[REDACTED] | UID=[REDACTED]  '
      );

      const partial = Redact.applyRedaction(text, spans, 'partial');
      assertEqual(
        partial.sanitizedText,
        '  Lead:\n\tEmail=r***@g***.com | Phone=XXXXXX3210\r\n\tPAN=XXXXX1234X | Card=XXXX-XXXX-XXXX-1111 | IP=XXX.XXX.XXX.XXX | UID=XXXX XXXX 0123  '
      );

      const pseudo = Redact.applyRedaction(text, spans, 'pseudonym');
      assertEqual(
        pseudo.sanitizedText,
        '  Lead:\n\tEmail=USER_01 | Phone=PHONE_01\r\n\tPAN=PAN_01 | Card=CARD_01 | IP=IP_01 | UID=AADHAAR_01  '
      );
    });

    test('Empty input produces zero counters and no errors', function () {
      const spans = Detectors.classifyEntities('');
      const res = Redact.applyRedaction('', spans, 'full');
      const summary = Audit.generateAuditSummary({
        spans: spans,
        replacements: res.replacements,
        mode: 'full',
        fileType: 'None',
        status: 'Idle'
      });
      assertEqual(spans.length, 0);
      assertEqual(res.sanitizedText, '');
      assertEqual(summary.totalDetected, 0);
      assertEqual(summary.entitiesRedacted, 0);
      assertEqual(summary.counts.email, 0);
      assertEqual(summary.counts.card, 0);
    });

    test('Sample dataset classifies expected entities and rejects invalid ones', function () {
      const spans = Detectors.classifyEntities(Sample.SAMPLE_TEXT);
      const summary = Audit.generateAuditSummary({
        spans: spans,
        replacements: spans,
        mode: 'full',
        fileType: 'Text',
        status: 'Complete'
      });
      assertEqual(summary.counts.email, 3);
      assertEqual(summary.counts.phone, 3);
      assertEqual(summary.counts.ipv4, 2);
      assertEqual(summary.counts.pan, 1);
      assertEqual(summary.counts.aadhaar, 1);
      assertEqual(summary.counts.card, 2);
      assertEqual(summary.totalDetected, 12);
    });

    test('Upload validation accepts .txt/.csv and rejects non-.txt/.csv', function () {
      assertEqual(Export.validateUploadFile({ name: 'report.txt' }).fileType, 'TXT');
      assertEqual(Export.validateUploadFile({ name: 'EXPORT.CSV' }).fileType, 'CSV');
      assert(!Export.validateUploadFile({ name: 'payload.exe' }).ok, '.exe must be rejected');
      assert(!Export.validateUploadFile({ name: 'notes.pdf' }).ok, '.pdf must be rejected');
    });

    test('TXT and CSV sanitized downloads contain zero original sensitive values', async function () {
      const csvInput = [
        'name,email,phone,pan,card',
        'Row1,ananya.sharma@example.org,+91 98765-43210,ABCDE1234F,4111 1111 1111 1111',
        'Row2,sec.ops@veil-demo.test,9876543210,ABCDE1234F,5555 5555 5555 4444'
      ].join('\n');

      const sensitiveValues = [
        'ananya.sharma@example.org',
        '+91 98765-43210',
        '9876543210',
        'ABCDE1234F',
        '4111 1111 1111 1111',
        'sec.ops@veil-demo.test',
        '5555 5555 5555 4444'
      ];

      const spans = Detectors.classifyEntities(csvInput);
      const redacted = Redact.applyRedaction(csvInput, spans, 'full');

      for (let i = 0; i < sensitiveValues.length; i++) {
        assert(
          !redacted.sanitizedText.includes(sensitiveValues[i]),
          'Sanitized CSV must not contain original value: ' + sensitiveValues[i]
        );
      }

      if (isNode) {
        const capturedBlobs = [];
        let revokedCount = 0;
        const origBlob = global.Blob;
        const origURL = global.URL;
        const origDoc = global.document;

        try {
          global.Blob = function (parts, opts) {
            this.text = parts.join('');
            this.type = opts && opts.type;
            capturedBlobs.push(this);
          };
          global.URL = {
            createObjectURL: function () { return 'blob:veil-test'; },
            revokeObjectURL: function () { revokedCount += 1; }
          };
          global.document = {
            createElement: function () {
              return { style: {}, click: function () {} };
            },
            body: {
              appendChild: function () {},
              removeChild: function () {}
            }
          };

          const txtOut = Export.downloadSanitizedFile(redacted.sanitizedText, {
            format: 'txt',
            originalName: 'customers.txt'
          });
          const csvOut = Export.downloadSanitizedFile(redacted.sanitizedText, {
            format: 'csv',
            originalName: 'customers.csv'
          });

          assert(txtOut.ok && csvOut.ok, 'Both TXT and CSV downloads should succeed');
          assertEqual(capturedBlobs.length, 2);
          for (let b = 0; b < capturedBlobs.length; b++) {
            for (let s = 0; s < sensitiveValues.length; s++) {
              assert(
                !capturedBlobs[b].text.includes(sensitiveValues[s]),
                'Downloaded blob leaked original value: ' + sensitiveValues[s]
              );
            }
          }
          await new Promise(function (resolve) { setTimeout(resolve, 1050); });
          assertEqual(revokedCount, 2, 'Object URLs must be revoked after download');
        } finally {
          global.Blob = origBlob;
          global.URL = origURL;
          global.document = origDoc;
        }
      }
    });

    test('Large input (500 KB+) processes cleanly without error', function () {
      const chunk = '2026-11-27 ORD-1001 user@example.com +91 9876543210 192.168.1.10 ABCDE1234F 4111 1111 1111 1111\n';
      const largeText = chunk.repeat(6000); // ~540 KB
      assert(largeText.length > 500000, 'Test payload must exceed 500 KB');
      const t0 = Date.now();
      const spans = Detectors.classifyEntities(largeText);
      const res = Redact.applyRedaction(largeText, spans, 'pseudonym');
      const elapsed = Date.now() - t0;
      assertEqual(spans.length, 30000, 'Expected 5 entities per line * 6000 lines');
      assert(!res.sanitizedText.includes('user@example.com'), 'All emails must be redacted in large payload');
      assert(elapsed < 4000, '500 KB+ processing took too long: ' + elapsed + ' ms');
    });

    if (isNode) {
      test('Hard constraint static audit: no network calls, storage, or innerHTML in source files', function () {
        const fs = require('fs');
        const path = require('path');
        const filesToCheck = [
          '../index.html',
          '../src/styles.css',
          '../src/detectors.js',
          '../src/redact.js',
          '../src/audit.js',
          '../src/export.js',
          '../src/sample.js',
          '../src/main.js'
        ];
        const forbidden = [
          'innerHTML',
          'localStorage',
          'sessionStorage',
          'indexedDB',
          'document.cookie',
          'XMLHttpRequest',
          'fetch(',
          'http://',
          'https://'
        ];
        for (let i = 0; i < filesToCheck.length; i++) {
          const content = fs.readFileSync(path.join(__dirname, filesToCheck[i]), 'utf8');
          for (let j = 0; j < forbidden.length; j++) {
            assert(
              !content.includes(forbidden[j]),
              'Forbidden pattern "' + forbidden[j] + '" found in ' + filesToCheck[i]
            );
          }
          if (filesToCheck[i].endsWith('.js')) {
            assert(!content.includes('console.log'), 'console.log found in ' + filesToCheck[i]);
          }
        }
      });
    }

    return cases;
  }

  function runAllTests() {
    const cases = buildTestCases();
    const results = [];
    let passed = 0;
    let failed = 0;

    // Note: download test is async; handle both sync and promise-returning tests sequentially via sync/async helper
    let hasAsync = false;
    for (let i = 0; i < cases.length; i++) {
      const c = cases[i];
      try {
        const maybePromise = c.fn();
        if (maybePromise && typeof maybePromise.then === 'function') {
          hasAsync = true;
        }
        results.push({ name: c.name, pass: true, error: null });
        passed += 1;
      } catch (err) {
        results.push({ name: c.name, pass: false, error: err && err.message ? err.message : String(err) });
        failed += 1;
      }
    }

    void hasAsync;
    return { total: cases.length, passed: passed, failed: failed, results: results };
  }

  async function runAllTestsAsync() {
    const cases = buildTestCases();
    const results = [];
    let passed = 0;
    let failed = 0;

    for (let i = 0; i < cases.length; i++) {
      const c = cases[i];
      try {
        await c.fn();
        results.push({ name: c.name, pass: true, error: null });
        passed += 1;
      } catch (err) {
        results.push({ name: c.name, pass: false, error: err && err.message ? err.message : String(err) });
        failed += 1;
      }
    }
    return { total: cases.length, passed: passed, failed: failed, results: results };
  }

  return {
    runAllTests: runAllTests,
    runAllTestsAsync: runAllTestsAsync
  };
});
