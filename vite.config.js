import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  base: './',
  plugins: [
    react(),
    tailwindcss(),
  ],
  server: {
    proxy: {
      // Proxy para AbuseIPDB — contorna CORS no browser
      '/api/abuseipdb': {
        target: 'https://api.abuseipdb.com',
        changeOrigin: true,
        secure: true,
        rewrite: (path) => path.replace(/^\/api\/abuseipdb/, ''),
      },
      // Proxy para VirusTotal — contorna CORS no browser
      '/api/virustotal': {
        target: 'https://www.virustotal.com',
        changeOrigin: true,
        secure: true,
        rewrite: (path) => path.replace(/^\/api\/virustotal/, ''),
      },
    },
  },
})
