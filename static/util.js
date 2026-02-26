// ── Shared Utilities ──────────────────────────────────────────────

/** HTML-escape a string for safe innerHTML insertion. */
function esc(str) {
  return String(str ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

/** Convert entity_id dots to hyphens for use in DOM IDs. */
function cssId(s) { return s.replace(/\./g, '-'); }

// ── Focus Trap (for modal dialogs) ───────────────────────────────
let _previouslyFocused = null;

const _FOCUSABLE_SELECTOR =
  'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';

function trapFocus(modal) {
  _previouslyFocused = document.activeElement;
  const focusable = modal.querySelectorAll(_FOCUSABLE_SELECTOR);
  if (!focusable.length) return;
  focusable[0].focus();
  modal.addEventListener('keydown', _handleTrapKeydown);
}

function _handleTrapKeydown(e) {
  if (e.key !== 'Tab') return;
  const focusable = this.querySelectorAll(_FOCUSABLE_SELECTOR);
  if (!focusable.length) return;
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (e.shiftKey && document.activeElement === first) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && document.activeElement === last) {
    e.preventDefault();
    first.focus();
  }
}

function releaseFocus() {
  if (_previouslyFocused && typeof _previouslyFocused.focus === 'function') {
    _previouslyFocused.focus();
  }
  _previouslyFocused = null;
}
