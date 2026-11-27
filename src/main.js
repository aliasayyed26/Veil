(function () {
  'use strict';

  const Detectors = window.Veil && window.Veil.Detectors;
  const Redact = window.Veil && window.Veil.Redact;
  const Audit = window.Veil && window.Veil.Audit;
  const Export = window.Veil && window.Veil.Export;
  const Sample = window.Veil && window.Veil.Sample;
  const Motion = window.Veil && window.Veil.Motion;

  const TYPE_LABELS = Object.freeze({
    email: 'Email',
    phone: 'Phone',
    ipv4: 'IPv4',
    pan: 'PAN',
    aadhaar: 'Aadhaar',
    card: 'Credit Card'
  });

  const DEBOUNCE_MS = 120;

  const state = {
    mode: 'full',
    fileType: 'None',
    fileName: '',
    status: 'Idle',
    spans: [],
    sanitizedText: '',
    replacements: [],
    prevCounts: { email: 0, phone: 0, ipv4: 0, pan: 0, aadhaar: 0, card: 0, total: 0 },
    debounceTimer: null,
    toastTimer: null,
    copyTimer: null,
    resetTimer: null,
    runId: 0
  };

  const dom = {
    sourceInput: document.getElementById('sourceInput'),
    inputMeta: document.getElementById('inputMeta'),
    dropzone: document.getElementById('dropzone'),
    fileInput: document.getElementById('fileInput'),
    pasteBtn: document.getElementById('pasteBtn'),
    uploadTriggerBtn: document.getElementById('uploadTriggerBtn'),
    sampleBtn: document.getElementById('sampleBtn'),
    clearBtn: document.getElementById('clearBtn'),
    topResetBtn: document.getElementById('topResetBtn'),
    exportResetBtn: document.getElementById('exportResetBtn'),
    motionToggleBtn: document.getElementById('motionToggleBtn'),
    clientBadge: document.getElementById('clientBadge'),
    feedbackBar: document.getElementById('feedbackBar'),
    srAnnounce: document.getElementById('srAnnounce'),
    countEmail: document.getElementById('countEmail'),
    countPhone: document.getElementById('countPhone'),
    countIpv4: document.getElementById('countIpv4'),
    countPan: document.getElementById('countPan'),
    countAadhaar: document.getElementById('countAadhaar'),
    countCard: document.getElementById('countCard'),
    countTotal: document.getElementById('countTotal'),
    modeControl: document.getElementById('modeControl'),
    diffGrid: document.getElementById('diffGrid'),
    originalPreview: document.getElementById('originalPreview'),
    originalStage: document.getElementById('originalStage'),
    sanitizedPreview: document.getElementById('sanitizedPreview'),
    sanitizedStage: document.getElementById('sanitizedStage'),
    telemetryRack: document.querySelector('.telemetry-rack'),
    downloadTxtBtn: document.getElementById('downloadTxtBtn'),
    downloadCsvBtn: document.getElementById('downloadCsvBtn'),
    copyBtn: document.getElementById('copyBtn'),
    exportMessage: document.getElementById('exportMessage'),
    auditStatusBadge: document.getElementById('auditStatusBadge'),
    auditDetected: document.getElementById('auditDetected'),
    auditRedacted: document.getElementById('auditRedacted'),
    auditMode: document.getElementById('auditMode'),
    auditFileType: document.getElementById('auditFileType'),
    auditStatus: document.getElementById('auditStatus'),
    promptLogList: document.getElementById('promptLogList')
  };

  function setFeedback(message, kind) {
    if (state.toastTimer) {
      clearTimeout(state.toastTimer);
      state.toastTimer = null;
    }
    if (!message) {
      dom.feedbackBar.classList.remove('is-visible');
      dom.feedbackBar.textContent = '';
      return;
    }
    dom.feedbackBar.textContent = message;
    dom.feedbackBar.className = 'feedback-bar' + (kind ? ' is-' + kind : '');
    void dom.feedbackBar.offsetWidth;
    dom.feedbackBar.classList.add('is-visible');

    state.toastTimer = setTimeout(function () {
      state.toastTimer = null;
      dom.feedbackBar.classList.remove('is-visible');
    }, 3200);
  }

  function setExportMessage(message, kind) {
    dom.exportMessage.textContent = message || '';
    dom.exportMessage.className = 'export-note' + (kind ? ' is-' + kind : '');
  }

  function announceFinalSummary(summary) {
    if (!dom.srAnnounce) return;
    if (summary.totalDetected === 0) {
      dom.srAnnounce.textContent = 'Scan complete. No matching PII detected.';
    } else {
      dom.srAnnounce.textContent =
        'Scan complete. ' + summary.totalDetected + ' entities detected and redacted in ' + summary.selectedMode + ' mode.';
    }
  }

  function updateInputMeta(text) {
    const length = text.length;
    const kb = (new Blob([text]).size / 1024).toFixed(1);
    dom.inputMeta.textContent = length.toLocaleString() + ' chars \u2022 ' + kb + ' KB';
  }

  function setStatus(status) {
    state.status = status;
    dom.auditStatus.textContent = status;
    dom.auditStatusBadge.textContent = status;
    dom.auditStatusBadge.setAttribute('data-status', status);
  }

  function triggerDownloadSweep(btn) {
    if (!btn || Motion.prefersReducedMotion()) return;
    btn.classList.remove('is-downloading');
    void btn.offsetWidth;
    btn.classList.add('is-downloading');
  }

  function triggerCrossfade(stageEl) {
    if (!stageEl || Motion.prefersReducedMotion()) return;
    stageEl.classList.remove('is-crossfading');
    void stageEl.offsetWidth;
    stageEl.classList.add('is-crossfading');
  }

  function updateCounterElement(valueEl, prevCount, nextCount) {
    const card = valueEl.closest('.counter-card');
    if (card) {
      card.classList.toggle('has-matches', nextCount > 0);
      if (nextCount > prevCount && !Motion.prefersReducedMotion()) {
        card.classList.remove('is-glow');
        void card.offsetWidth;
        card.classList.add('is-glow');
      } else if (nextCount === 0) {
        card.classList.remove('is-glow');
      }
    }
    Motion.animateCounter(valueEl, prevCount, nextCount, { duration: 400 });
  }

  function createEmptySkeleton(emptyMessage) {
    const wrap = document.createElement('div');
    wrap.className = 'diff-empty-wrap';

    const label = document.createElement('span');
    label.className = 'diff-empty';
    label.textContent = emptyMessage;
    wrap.appendChild(label);

    const lines = document.createElement('div');
    lines.className = 'diff-skeleton-lines';
    const widths = ['', 'mid', 'short'];
    for (let i = 0; i < widths.length; i++) {
      const line = document.createElement('div');
      line.className = 'skeleton-line' + (widths[i] ? ' ' + widths[i] : '');
      lines.appendChild(line);
    }
    wrap.appendChild(lines);
    return wrap;
  }

  function buildLinkGroupIds(replacements, mode) {
    if (mode !== 'pseudonym' || !Array.isArray(replacements) || replacements.length === 0) {
      return null;
    }
    const groupMap = new Map();
    let nextId = 0;
    const ids = new Array(replacements.length);
    for (let i = 0; i < replacements.length; i++) {
      const token = replacements[i].replacement;
      let groupId = groupMap.get(token);
      if (groupId === undefined) {
        groupId = String(nextId++);
        groupMap.set(token, groupId);
      }
      ids[i] = groupId;
    }
    groupMap.clear();
    return ids;
  }

  function renderHighlightedText(container, text, spans, emptyMessage, linkGroupIds) {
    if (!text) {
      container.replaceChildren(createEmptySkeleton(emptyMessage));
      return [];
    }

    const fragment = document.createDocumentFragment();
    const tokenElements = [];
    let cursor = 0;

    for (let i = 0; i < spans.length; i++) {
      const span = spans[i];
      if (span.start > cursor) {
        fragment.appendChild(document.createTextNode(text.slice(cursor, span.start)));
      }
      const tokenEl = document.createElement('span');
      const label = TYPE_LABELS[span.type] || span.type;
      const tooltip = label + (span.note ? ' \u2022 ' + span.note : '');

      tokenEl.className = 'pii-token pii-' + span.type;
      tokenEl.textContent = text.slice(span.start, span.end);
      tokenEl.setAttribute('tabindex', '0');
      tokenEl.setAttribute('title', tooltip);
      tokenEl.setAttribute('data-tooltip', tooltip);
      tokenEl.setAttribute('aria-label', tooltip);
      if (linkGroupIds && linkGroupIds[i] !== undefined) {
        tokenEl.setAttribute('data-link-group', linkGroupIds[i]);
      }
      fragment.appendChild(tokenEl);
      tokenElements.push(tokenEl);

      cursor = span.end;
    }

    if (cursor < text.length) {
      fragment.appendChild(document.createTextNode(text.slice(cursor)));
    }

    container.replaceChildren(fragment);
    return tokenElements;
  }

  function renderCountersAndAudit(summary, finalStatus) {
    const prev = state.prevCounts;
    updateCounterElement(dom.countEmail, prev.email, summary.counts.email);
    updateCounterElement(dom.countPhone, prev.phone, summary.counts.phone);
    updateCounterElement(dom.countIpv4, prev.ipv4, summary.counts.ipv4);
    updateCounterElement(dom.countPan, prev.pan, summary.counts.pan);
    updateCounterElement(dom.countAadhaar, prev.aadhaar, summary.counts.aadhaar);
    updateCounterElement(dom.countCard, prev.card, summary.counts.card);
    updateCounterElement(dom.countTotal, prev.total, summary.totalDetected);

    state.prevCounts = {
      email: summary.counts.email,
      phone: summary.counts.phone,
      ipv4: summary.counts.ipv4,
      pan: summary.counts.pan,
      aadhaar: summary.counts.aadhaar,
      card: summary.counts.card,
      total: summary.totalDetected
    };

    dom.auditDetected.textContent = String(summary.totalDetected);
    dom.auditRedacted.textContent = String(summary.entitiesRedacted);
    dom.auditMode.textContent = summary.selectedMode;
    dom.auditFileType.textContent = summary.fileType;
    if (dom.telemetryRack) {
      dom.telemetryRack.classList.toggle('has-active', summary.totalDetected > 0);
    }
    setStatus(finalStatus);
  }

  function updateCsvButtonState(hasContent) {
    dom.downloadCsvBtn.disabled = !(hasContent && state.fileType === 'CSV');
  }

  function runSanitizedScramble(tokenElements, replacements) {
    if (Motion.prefersReducedMotion()) return;
    if (tokenElements.length === 0 || tokenElements.length > Motion.MAX_STAGGER_ITEMS) return;

    const count = tokenElements.length;
    const step = Math.min(18, Math.floor(180 / count));
    for (let i = 0; i < count; i++) {
      const targetText = replacements[i] ? replacements[i].replacement : tokenElements[i].textContent;
      Motion.scrambleResolve(tokenElements[i], targetText, {
        duration: 300,
        delay: i * step
      });
    }
  }

  function processDocument(redetect, options) {
    const opts = options || {};
    const heroSweep = Boolean(opts.heroSweep);
    const modeChanged = Boolean(opts.modeChanged);
    const currentRunId = ++state.runId;

    Motion.cancelAll();

    const text = dom.sourceInput.value;
    updateInputMeta(text);

    if (!text) {
      state.spans = [];
      state.sanitizedText = '';
      state.replacements = [];
      renderHighlightedText(dom.originalPreview, '', [], 'No document loaded yet.', null);
      renderHighlightedText(dom.sanitizedPreview, '', [], 'Sanitized output will appear here.', null);
      const emptySummary = Audit.generateAuditSummary({
        spans: [],
        replacements: [],
        mode: state.mode,
        fileType: state.fileType,
        status: 'Idle'
      });
      renderCountersAndAudit(emptySummary, 'Idle');
      updateCsvButtonState(false);
      setExportMessage('Enter text or upload a file to enable sanitized export.', '');
      return;
    }

    try {
      setStatus('Scanning');

      if (redetect) {
        state.spans = Detectors.classifyEntities(text);
      }

      const result = Redact.applyRedaction(text, state.spans, state.mode);
      state.sanitizedText = result.sanitizedText;
      state.replacements = result.replacements;

      const linkGroupIds = buildLinkGroupIds(state.replacements, state.mode);

      if (redetect || modeChanged) {
        renderHighlightedText(dom.originalPreview, text, state.spans, 'No document loaded yet.', linkGroupIds);
      }
      const sanitizedTokens = renderHighlightedText(
        dom.sanitizedPreview,
        state.sanitizedText,
        state.replacements,
        'Sanitized output will appear here.',
        linkGroupIds
      );

      if (modeChanged) {
        triggerCrossfade(dom.sanitizedStage);
      }

      runSanitizedScramble(sanitizedTokens, state.replacements);

      const summary = Audit.generateAuditSummary({
        spans: state.spans,
        replacements: state.replacements,
        mode: state.mode,
        fileType: state.fileType,
        status: 'Complete'
      });

      const willSweep = heroSweep && !Motion.prefersReducedMotion();
      renderCountersAndAudit(summary, willSweep ? 'Scanning' : 'Complete');
      updateCsvButtonState(true);

      if (state.spans.length === 0) {
        setExportMessage('No matching PII patterns found. You can still download or copy the text.', '');
      } else {
        setExportMessage(
          'Ready to export ' + state.spans.length + ' redacted entit' + (state.spans.length === 1 ? 'y' : 'ies') + '.',
          ''
        );
      }

      if (willSweep) {
        const sweepPromise = Motion.runScanSweep(dom.originalStage, { duration: 800 });
        Motion.revealHighlights(dom.originalStage, { baseDelay: 40 });
        sweepPromise.then(function (res) {
          if (currentRunId !== state.runId || (res && res.cancelled)) return;
          setStatus('Complete');
          announceFinalSummary(summary);
        });
      } else {
        if (redetect && !Motion.prefersReducedMotion()) {
          Motion.revealHighlights(dom.originalStage, { baseDelay: 0 });
        }
        announceFinalSummary(summary);
      }
    } catch (err) {
      state.spans = [];
      state.sanitizedText = '';
      state.replacements = [];
      setStatus('Error');
      setFeedback('Processing failed: ' + (err && err.message ? err.message : 'Unexpected error.'), 'error');
      setExportMessage('Unable to export while processing is in an error state.', 'error');
      updateCsvButtonState(false);
    }
  }

  function scheduleProcess() {
    if (state.debounceTimer) {
      clearTimeout(state.debounceTimer);
    }
    setStatus(dom.sourceInput.value ? 'Scanning' : 'Idle');
    state.debounceTimer = setTimeout(function () {
      state.debounceTimer = null;
      processDocument(true, { heroSweep: false });
    }, DEBOUNCE_MS);
  }

  function performResetClear() {
    dom.sourceInput.value = '';
    dom.fileInput.value = '';
    state.fileType = 'None';
    state.fileName = '';
    state.spans = [];
    state.sanitizedText = '';
    state.replacements = [];
    if (dom.originalStage) dom.originalStage.classList.remove('is-fading-out');
    if (dom.sanitizedStage) dom.sanitizedStage.classList.remove('is-fading-out');
    setFeedback('Document, counters, and in-memory mappings cleared.', 'success');
    processDocument(true, { heroSweep: false });
  }

  function resetAll() {
    if (state.debounceTimer) {
      clearTimeout(state.debounceTimer);
      state.debounceTimer = null;
    }
    if (state.resetTimer) {
      clearTimeout(state.resetTimer);
      state.resetTimer = null;
    }
    Motion.cancelAll();

    const hasContent = Boolean(dom.sourceInput.value);
    if (!hasContent || Motion.prefersReducedMotion()) {
      performResetClear();
      return;
    }

    if (dom.originalStage) dom.originalStage.classList.add('is-fading-out');
    if (dom.sanitizedStage) dom.sanitizedStage.classList.add('is-fading-out');

    state.resetTimer = setTimeout(function () {
      state.resetTimer = null;
      performResetClear();
    }, 150);
  }

  function loadFile(file) {
    const validation = Export.validateUploadFile(file);
    if (!validation.ok) {
      setFeedback(validation.message, 'error');
      dom.fileInput.value = '';
      return;
    }

    const reader = new FileReader();
    reader.onload = function (event) {
      const content = typeof event.target.result === 'string' ? event.target.result : '';
      if (content.indexOf('\0') !== -1) {
        setFeedback('File appears to contain binary data and was rejected.', 'error');
        dom.fileInput.value = '';
        return;
      }
      state.fileType = validation.fileType;
      state.fileName = file.name;
      dom.sourceInput.value = content;
      setFeedback('Loaded ' + validation.fileType + ' file locally in memory.', 'success');
      processDocument(true, { heroSweep: true });
    };
    reader.onerror = function () {
      setFeedback('Could not read the selected file.', 'error');
      setStatus('Error');
    };
    reader.readAsText(file);
  }

  function initModeControl() {
    const buttons = dom.modeControl.querySelectorAll('.segment-btn');
    buttons.forEach(function (btn) {
      btn.addEventListener('click', function () {
        const nextMode = btn.getAttribute('data-mode');
        const nextIndex = btn.getAttribute('data-index') || '0';
        if (!nextMode || nextMode === state.mode) return;
        state.mode = nextMode;
        dom.modeControl.style.setProperty('--mode-index', nextIndex);
        buttons.forEach(function (item) {
          const active = item === btn;
          item.classList.toggle('is-active', active);
          item.setAttribute('aria-checked', active ? 'true' : 'false');
        });
        processDocument(false, { modeChanged: true });
      });
    });
  }

  function initMotionToggle() {
    function syncButton() {
      const enabled = Motion.isMotionEnabled();
      dom.motionToggleBtn.textContent = 'Animations: ' + (enabled ? 'On' : 'Off');
      dom.motionToggleBtn.setAttribute('aria-pressed', enabled ? 'true' : 'false');
    }

    syncButton();
    dom.motionToggleBtn.addEventListener('click', function () {
      Motion.setUserMotionPreference(!Motion.isMotionEnabled());
      syncButton();
    });
  }

  function initPseudonymLinkHighlighting() {
    let activeGroup = null;

    function setLinkedGroup(groupId) {
      if (activeGroup === groupId) return;
      if (activeGroup !== null) {
        const prevEls = dom.diffGrid.querySelectorAll('.pii-token.is-linked');
        for (let i = 0; i < prevEls.length; i++) {
          prevEls[i].classList.remove('is-linked');
        }
      }
      activeGroup = groupId;
      if (groupId !== null && state.mode === 'pseudonym') {
        const matches = dom.diffGrid.querySelectorAll('.pii-token[data-link-group="' + groupId + '"]');
        for (let j = 0; j < matches.length; j++) {
          matches[j].classList.add('is-linked');
        }
      }
    }

    function handleEnter(event) {
      if (state.mode !== 'pseudonym') return;
      const token = event.target && event.target.closest ? event.target.closest('.pii-token[data-link-group]') : null;
      if (!token) return;
      setLinkedGroup(token.getAttribute('data-link-group'));
    }

    function handleLeave(event) {
      if (!activeGroup) return;
      const related = event.relatedTarget && event.relatedTarget.closest
        ? event.relatedTarget.closest('.pii-token[data-link-group]')
        : null;
      if (related && related.getAttribute('data-link-group') === activeGroup) {
        return;
      }
      setLinkedGroup(null);
    }

    dom.diffGrid.addEventListener('mouseover', handleEnter);
    dom.diffGrid.addEventListener('mouseout', handleLeave);
    dom.diffGrid.addEventListener('focusin', handleEnter);
    dom.diffGrid.addEventListener('focusout', handleLeave);
  }

  function initPromptLog() {
    const logs = Sample && Array.isArray(Sample.PROMPT_LOG) ? Sample.PROMPT_LOG : [];
    const fragment = document.createDocumentFragment();
    for (let i = 0; i < logs.length; i++) {
      const li = document.createElement('li');
      li.textContent = logs[i].prompt;
      fragment.appendChild(li);
    }
    dom.promptLogList.replaceChildren(fragment);
  }

  function initEvents() {
    dom.sourceInput.addEventListener('input', function () {
      if (dom.sourceInput.value && state.fileType === 'None') {
        state.fileType = 'Text';
      } else if (!dom.sourceInput.value) {
        state.fileType = 'None';
        state.fileName = '';
      }
      setFeedback('', '');
      scheduleProcess();
    });

    dom.sourceInput.addEventListener('paste', function () {
      // Trigger hero scan sweep after browser inserts pasted text
      setTimeout(function () {
        if (state.debounceTimer) {
          clearTimeout(state.debounceTimer);
          state.debounceTimer = null;
        }
        if (dom.sourceInput.value && state.fileType === 'None') {
          state.fileType = 'Text';
        }
        processDocument(true, { heroSweep: true });
      }, 0);
    });

    dom.pasteBtn.addEventListener('click', async function () {
      if (!navigator.clipboard || typeof navigator.clipboard.readText !== 'function') {
        setFeedback('Clipboard read is unavailable in this browser context. Paste directly with Ctrl+V / Cmd+V.', 'error');
        dom.sourceInput.focus();
        return;
      }
      try {
        const clipText = await navigator.clipboard.readText();
        if (!clipText) {
          setFeedback('Clipboard is empty.', '');
          return;
        }
        dom.sourceInput.value = clipText;
        state.fileType = 'Text';
        state.fileName = '';
        setFeedback('Pasted text from clipboard into local memory.', 'success');
        processDocument(true, { heroSweep: true });
      } catch (_err) {
        setFeedback('Clipboard permission denied. Paste directly into the editor with Ctrl+V / Cmd+V.', 'error');
        dom.sourceInput.focus();
      }
    });

    dom.uploadTriggerBtn.addEventListener('click', function () {
      dom.fileInput.click();
    });

    dom.fileInput.addEventListener('change', function (event) {
      const file = event.target.files && event.target.files[0];
      if (file) {
        loadFile(file);
      }
    });

    dom.dropzone.addEventListener('dragover', function (event) {
      event.preventDefault();
      dom.dropzone.classList.add('is-dragover');
    });

    dom.dropzone.addEventListener('dragleave', function (event) {
      if (event.relatedTarget && dom.dropzone.contains(event.relatedTarget)) return;
      dom.dropzone.classList.remove('is-dragover');
    });

    dom.dropzone.addEventListener('drop', function (event) {
      event.preventDefault();
      dom.dropzone.classList.remove('is-dragover');
      const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
      if (file) {
        loadFile(file);
      }
    });

    dom.sampleBtn.addEventListener('click', function () {
      dom.sourceInput.value = Sample.SAMPLE_TEXT;
      state.fileType = 'Text';
      state.fileName = 'sample-test-data.txt';
      setFeedback('Loaded synthetic sample dataset (no real PII).', 'success');
      processDocument(true, { heroSweep: true });
    });

    dom.clearBtn.addEventListener('click', resetAll);
    dom.topResetBtn.addEventListener('click', resetAll);
    dom.exportResetBtn.addEventListener('click', resetAll);

    dom.downloadTxtBtn.addEventListener('click', function () {
      const res = Export.downloadSanitizedFile(state.sanitizedText, {
        format: 'txt',
        originalName: state.fileName
      });
      if (res.ok) {
        triggerDownloadSweep(dom.downloadTxtBtn);
      }
      setExportMessage(res.message, res.ok ? 'success' : 'error');
    });

    dom.downloadCsvBtn.addEventListener('click', function () {
      if (state.fileType !== 'CSV') {
        setExportMessage('CSV download is only enabled when a .csv file is loaded.', 'error');
        return;
      }
      const res = Export.downloadSanitizedFile(state.sanitizedText, {
        format: 'csv',
        originalName: state.fileName
      });
      if (res.ok) {
        triggerDownloadSweep(dom.downloadCsvBtn);
      }
      setExportMessage(res.message, res.ok ? 'success' : 'error');
    });

    dom.copyBtn.addEventListener('click', async function () {
      const res = await Export.copy(state.sanitizedText);
      setExportMessage(res.message, res.ok ? 'success' : 'error');
      if (res.ok) {
        if (state.copyTimer) {
          clearTimeout(state.copyTimer);
        }
        dom.copyBtn.textContent = '\u2713 Copied';
        dom.copyBtn.classList.add('is-copied');
        state.copyTimer = setTimeout(function () {
          state.copyTimer = null;
          dom.copyBtn.textContent = 'Copy sanitized text';
          dom.copyBtn.classList.remove('is-copied');
        }, 1600);
      }
    });
  }

  function init() {
    Motion.initVisibilityController([dom.clientBadge, dom.diffGrid]);
    initMotionToggle();
    initModeControl();
    initPseudonymLinkHighlighting();
    initPromptLog();
    initEvents();
    processDocument(true, { heroSweep: false });
  }

  init();
})();
