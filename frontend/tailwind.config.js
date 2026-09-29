/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#090D16',
          card: '#111726',
          border: '#1F293D',
          hover: '#182238',
          accent: '#3B82F6',
          cyan: '#06B6D4',
          emerald: '#10B981',
          amber: '#F59E0B',
          crimson: '#EF4444',
          muted: '#818CF8'
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace']
      }
    },
  },
  plugins: [],
}
