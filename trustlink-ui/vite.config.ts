import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

// 단일 오리진(TrustLink 프론트) 전제. 빌드 산출물은 BFF가 / 에서 서빙.
// 개발 시(npm run dev) /v2·/zot·/auth·/api 는 BFF(:8088)로 프록시.
export default defineConfig({
  plugins: [react()],
  resolve: { alias: { '@': path.resolve(__dirname, './src') } },
  server: {
    proxy: {
      '/v2': 'http://localhost:8088',
      '/zot': 'http://localhost:8088',
      '/auth': 'http://localhost:8088',
      '/api': 'http://localhost:8088'
    }
  },
  build: { outDir: 'dist' }
});
