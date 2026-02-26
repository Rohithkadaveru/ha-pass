// ── Theme Management (shared) ─────────────────────────────────────
const THEME_KEY = 'ha-theme';

function getThemePref() {
  return localStorage.getItem(THEME_KEY) || 'system';
}

function setTheme(pref) {
  localStorage.setItem(THEME_KEY, pref);
  const dark = pref === 'dark' || (pref === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
  document.documentElement.classList.toggle('dark', dark);
  updateThemeToggles();
}

function updateThemeToggles() {
  const pref = getThemePref();
  const offset = parseInt(document.body.dataset.themeOffset || '3', 10);
  document.querySelectorAll('.theme-toggle').forEach(toggle => {
    const slider = toggle.querySelector('.theme-slider');
    const activeBtn = toggle.querySelector(`[data-theme="${pref}"]`);
    if (slider && activeBtn) {
      slider.style.width = activeBtn.offsetWidth + 'px';
      slider.style.transform = `translateX(${activeBtn.offsetLeft - offset}px)`;
    }
    toggle.querySelectorAll('.theme-btn').forEach(btn => {
      const icon = btn.querySelector('.material-symbols-outlined');
      if (icon) {
        icon.style.opacity = btn.dataset.theme === pref ? '1' : '0.65';
      }
    });
  });
}

window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
  if (getThemePref() === 'system') setTheme('system');
});
