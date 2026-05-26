import type { Config } from 'tailwindcss'

export default {
  darkMode: ['class'],
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          base: '#0d0d14',
          surface: '#13131f',
          elevated: '#1a1a2e',
        },
        border: '#2a2a3e',
        text: {
          primary: '#e8e8f0',
          muted: '#6b6b8a',
        },
        accent: {
          DEFAULT: '#7c3aed',
          bright: '#06b6d4',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'monospace'],
      },
      borderColor: {
        DEFAULT: '#2a2a3e',
      },
    },
  },
  plugins: [],
} satisfies Config
