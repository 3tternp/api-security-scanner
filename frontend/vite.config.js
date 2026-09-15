import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
  plugins: [
    react(),
    {
      name: 'favicon-no-404',
      configureServer(server) {
        server.middlewares.use('/favicon.ico', (req, res) => {
          res.statusCode = 204
          res.end()
        })
      },
      configurePreviewServer(server) {
        server.middlewares.use('/favicon.ico', (req, res) => {
          res.statusCode = 204
          res.end()
        })
      },
    },
  ],
})

