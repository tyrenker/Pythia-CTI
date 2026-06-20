import type { Config } from 'tailwindcss'

export default {
  darkMode: ['class'],
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          base: '#0a0a0f',
          surface: '#12121a',
          elevated: '#1c1c2e',
        },
        border: '#2a2a3a',
        text: {
          primary: '#e0e0e0',
          muted: '#6b7280',
        },
        accent: {
          DEFAULT: '#00ff88',
          bright: '#00ff88',
          secondary: '#ff00ff',
        },
        neon: {
          green: '#00ff88',
          cyan: '#00ff88',
          magenta: '#ff00ff',
          red: '#ff3366',
          amber: '#f59e0b',
        },
      },
      fontFamily: {
        sans: ['JetBrains Mono', 'ui-monospace', 'monospace'],
        mono: ['JetBrains Mono', 'ui-monospace', 'monospace'],
        display: ['Orbitron', 'monospace'],
      },
      borderColor: {
        DEFAULT: '#2a2a3a',
      },
      animation: {
        'blink': 'blink 1s step-end infinite',
        'glitch': 'glitch 10s ease-in-out infinite',
        'neon-pulse': 'neon-pulse 2s ease-in-out infinite',
        'scan': 'scan 8s linear infinite',
      },
      keyframes: {
        blink: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0' },
        },
        glitch: {
          '0%, 88%, 100%': { transform: 'translate(0)', clipPath: 'none' },
          '90%': { transform: 'translate(-2px, 1px)', clipPath: 'polygon(0 15%, 100% 15%, 100% 18%, 0 18%)' },
          '92%': { transform: 'translate(2px, -1px)', clipPath: 'polygon(0 65%, 100% 65%, 100% 68%, 0 68%)' },
          '94%': { transform: 'translate(-1px, 2px)', clipPath: 'none' },
          '96%': { transform: 'translate(0)' },
        },
        'neon-pulse': {
          '0%, 100%': { boxShadow: '0 0 5px #00ff88, 0 0 10px #00ff8840' },
          '50%': { boxShadow: '0 0 10px #00ff88, 0 0 25px #00ff8870, 0 0 50px #00ff8825' },
        },
        scan: {
          '0%': { backgroundPosition: '0 0' },
          '100%': { backgroundPosition: '0 200px' },
        },
      },
      boxShadow: {
        'neon': '0 0 5px #00ff88, 0 0 10px #00ff8840',
        'neon-sm': '0 0 3px #00ff88, 0 0 6px #00ff8830',
        'neon-lg': '0 0 10px #00ff88, 0 0 20px #00ff8860, 0 0 40px #00ff8830',
        'neon-cyan': '0 0 5px #00d4ff, 0 0 10px #00d4ff40',
        'neon-magenta': '0 0 5px #ff00ff, 0 0 10px #ff00ff40',
        'neon-red': '0 0 5px #ff3366, 0 0 10px #ff336640',
      },
    },
  },
  plugins: [],
} satisfies Config
