/*
 * DHC-3446 | Cybersecurity Internship 2026
 * middleware/authenticateToken.ts — JWT "Checkpoint" Gatekeeper
 *
 * Week 2 — "The Checkpoint":
 * This middleware checks for a valid JWT "wristband" before allowing
 * access to any sensitive action. Locked-down endpoints include:
 *
 *   CREATING  → POST /api/Products, POST /api/Users
 *   LISTING   → GET  /api/Users (admin), GET /api/Feedbacks
 *   DELETING  → DELETE /api/Addresss/:id, DELETE /api/Cards/:id (owner-only)
 *
 * Without a valid token the request is rejected with 401.
 * With a tampered/expired token it is rejected with 403.
 */

import { Request, Response, NextFunction } from 'express'
import jwt, { JwtPayload } from 'jsonwebtoken'

const JWT_SECRET = process.env.JWT_SECRET ?? 'dhc3446-replace-in-production'

export interface AuthRequest extends Request {
  user?: JwtPayload & { id: number; email: string; role: string }
}

export function authenticateToken (req: AuthRequest, res: Response, next: NextFunction): void {
  // Token expected in Authorization header as: Bearer <token>
  const authHeader = req.headers['authorization']
  const token = authHeader?.split(' ')[1]

  if (!token) {
    global.logger.warn(`Unauthorized access attempt — no token — ${req.method} ${req.path}`)
    res.status(401).json({ error: 'Access denied: authentication token required' })
    return
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as JwtPayload
    req.user = decoded as AuthRequest['user']
    next()
  } catch {
    global.logger.warn(`Invalid/expired token — ${req.method} ${req.path}`)
    res.status(403).json({ error: 'Access denied: invalid or expired token' })
  }
}

// Admin-only guard — use after authenticateToken
export function requireAdmin (req: AuthRequest, res: Response, next: NextFunction): void {
  if (req.user?.role !== 'admin') {
    global.logger.warn(`Non-admin tried admin route: ${req.user?.email ?? 'unknown'} — ${req.path}`)
    res.status(403).json({ error: 'Access denied: admin privileges required' })
    return
  }
  next()
}
