/*
 * DHC-3446 | Cybersecurity Internship 2026
 * server.ts — Patched Server Entry Point (forked from OWASP Juice Shop)
 *
 * Week 2 Fix — Helmet.js "Protective Suit":
 *   Added helmet() with a strict Content Security Policy (CSP).
 *   This tells the browser which scripts are trusted and blocks everything else.
 *   Even if an attacker sneaks a script onto the page, the browser checks the
 *   "trusted list" (CSP) and refuses to run it. Also blocks clickjacking via
 *   X-Frame-Options: DENY.
 *
 * Week 3 Fix — Winston "Black Box" Audit Trail:
 *   Integrated winston logger that writes all security events to security.log.
 *   Tracks: app start, all requests, failed logins, unauthorized access attempts.
 *   Gives us the "Who, What, and When" for every incident.
 */

import express from 'express'
import helmet from 'helmet'
import winston from 'winston'
import { login } from './routes/login'
import { search } from './routes/search'
import { authenticateToken } from './middleware/authenticateToken'

// ── Week 3: Winston "Black Box" Recorder ─────────────────────────────────────
// security.log is automatically generated and persisted on every run
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.printf(({ timestamp, level, message }) =>
      `[${timestamp as string}] ${level.toUpperCase()}: ${message as string}`)
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/security.log' })
  ]
})

// Make logger available globally so routes can write to it
;(global as any).logger = logger

const app = express()

// ── Week 2: Helmet.js — Full Protective Suit ──────────────────────────────────
// contentSecurityPolicy → browser only runs scripts from our domain
// frameguard → X-Frame-Options: DENY → stops clickjacking
// noSniff   → X-Content-Type-Options → stops MIME-sniffing
// hsts      → forces HTTPS in production
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],       // No inline scripts, no CDN scripts unless listed
      styleSrc:   ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc:    ["'self'"],
      objectSrc:  ["'none'"],
      frameSrc:   ["'none'"],       // Blocks all iframes — kills clickjacking
      upgradeInsecureRequests: []
    }
  },
  frameguard: { action: 'deny' },
  noSniff: true,
  referrerPolicy: { policy: 'no-referrer' }
}))

app.use(express.json({ limit: '10kb' }))
app.use(express.urlencoded({ extended: true }))

// ── Request Logging — every request recorded in security.log ──────────────────
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path} — IP: ${req.ip}`)
  next()
})

// ── Routes ─────────────────────────────────────────────────────────────────────
app.post('/rest/user/login', login())
app.get('/rest/products/search', search())

// Example protected route — requires valid JWT
app.get('/api/Users', authenticateToken, (req, res) => {
  res.json({ message: 'Admin user list — protected endpoint' })
})

// Health check
app.get('/', (req, res) => {
  res.json({ project: 'DHC-3446', app: 'OWASP Juice Shop (Patched)', status: 'running' })
})

// ── Global Error Handler — never leak stack traces to client ──────────────────
app.use((err: Error, req: express.Request, res: express.Response, _next: express.NextFunction) => {
  logger.error(`Unhandled error on ${req.method} ${req.path}: ${err.message}`)
  res.status(500).json({ error: 'Internal server error' })
})

const PORT = process.env.PORT ?? 3000
app.listen(PORT, () => {
  logger.info(`DHC-3446 patched Juice Shop running on port ${PORT}`)
  console.log(`Server running at http://localhost:${PORT}`)
})

export default app
