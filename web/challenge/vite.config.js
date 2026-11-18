import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Served by CloudFront under /challenge/ (see the "/challenge/*" cache behavior).
export default defineConfig({
  base: '/challenge/',
  plugins: [react()],
  server: { host: '127.0.0.1' },
  preview: { host: '127.0.0.1' },
  build: {
    outDir: 'dist',
    sourcemap: false,
    chunkSizeWarningLimit: 4096,
  },
});
