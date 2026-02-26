/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: ['./templates/**/*.html'],
  safelist: [
    'bg-amber-500', 'bg-amber-500/20',
    'bg-teal-600', 'bg-teal-600/20',
    'bg-blue-500', 'bg-blue-500/20',
    'bg-red-500', 'bg-red-500/20',
    'bg-purple-500', 'bg-purple-500/20',
    'bg-sky-500', 'bg-sky-500/20',
    'bg-emerald-500', 'bg-emerald-500/20',
    'bg-gray-500', 'bg-gray-500/20',
  ],
  theme: {
    extend: {
      colors: {
        primary:  { DEFAULT: 'rgb(var(--color-primary) / <alpha-value>)',
                    hover:   'rgb(var(--color-primary-hover) / <alpha-value>)' },
        surface:  { light: 'rgb(var(--color-surface-light) / <alpha-value>)',
                    dark:  'rgb(var(--color-surface-dark) / <alpha-value>)' },
        bg:       { light: 'rgb(var(--color-bg-light) / <alpha-value>)',
                    dark:  'rgb(var(--color-bg-dark) / <alpha-value>)' },
        border:   { light: 'rgb(var(--color-border-light) / <alpha-value>)',
                    dark:  'rgb(var(--color-border-dark) / <alpha-value>)' },
        accent:   'rgb(var(--color-accent) / <alpha-value>)',
        ink:      'rgb(var(--color-ink) / <alpha-value>)',
        muted:    'rgb(var(--color-muted) / <alpha-value>)',
        soot:     'rgb(var(--color-soot) / <alpha-value>)',
      },
      fontFamily: {
        display: ['"Work Sans"', 'sans-serif'],
        serif:   ['"Young Serif"', 'serif'],
        sans:    ['Karla', 'sans-serif'],
        mono:    ['"Space Mono"', 'monospace'],
      },
      boxShadow: {
        card: '0 2px 8px rgba(44, 36, 32, 0.08)',
      },
    },
  },
};
