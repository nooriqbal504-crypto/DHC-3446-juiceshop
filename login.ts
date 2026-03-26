/*
 * DHC-3446 | Cybersecurity Internship 2026
 * routes/login.ts — Patched Login Route (forked from OWASP Juice Shop)
 *
 * VULNERABILITY FIXED: SQL Injection — "The Master Key"
 * ──────────────────────────────────────────────────────
 * ORIGINAL JUICE SHOP CODE (intentionally vulnerable):
 *   models.sequelize.query(
 *     `SELECT * FROM Users WHERE email = '${req.body.email}'
 *      AND password = '${security.hash(req.body.password)}'`
 *   )
 *   Attack: email = ' OR 1=1 -- → entire WHERE clause becomes true → admin access granted.
 *
 * OUR FIX:
 *   - Input validated + sanitized with validator library
 *   - Sequelize findOne() with WHERE object (parameterized) — no raw SQL string building
 *   - bcrypt.compare() for constant-time password check
 *   - JWT signed token issued on success (expires 1h)
 */

import { Request, Response, NextFunction } from 'express'
import jwt from 'jsonwebtoken'
import validator from 'validator'
import bcrypt from 'bcrypt'
import { UserModel } from '../models/user'

const JWT_SECRET = process.env.JWT_SECRET ?? 'dhc3446-replace-with-secure-value-in-production'

export function login () {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { email, password } = req.body

      // Step 1: Validate — reject malformed input before it touches the DB
      if (!email || !password) {
        res.status(400).json({ error: 'Email and password are required' })
        return
      }

      if (!validator.isEmail(String(email))) {
        res.status(400).json({ error: 'Invalid email format' })
        return
      }

      const sanitizedEmail = validator.normalizeEmail(String(email)) as string

      // Step 2: Parameterized lookup — SQL injection is now impossible
      // findOne passes sanitizedEmail as a bound parameter to the DB driver.
      // ' OR 1=1 -- is treated as a plain string — it matches no email, returns null.
      const user = await UserModel.findOne({ where: { email: sanitizedEmail } })

      if (user == null) {
        // Run bcrypt anyway to prevent timing-based user enumeration
        await bcrypt.compare(String(password), '$2b$12$invalid.hash.for.timing.protection.x')
        global.logger.warn(`Failed login — unknown email: ${sanitizedEmail}`)
        res.status(401).json({ error: 'Invalid email or password' })
        return
      }

      // Step 3: bcrypt.compare — constant-time, safe password verification
      const isMatch = await bcrypt.compare(String(password), user.password)

      if (!isMatch) {
        global.logger.warn(`Failed login — wrong password for: ${sanitizedEmail}`)
        res.status(401).json({ error: 'Invalid email or password' })
        return
      }

      // Step 4: Issue JWT "VIP Pass" — signed, expires in 1 hour
      const token = jwt.sign(
        { id: user.id, email: user.email, role: user.role ?? 'customer' },
        JWT_SECRET,
        { expiresIn: '1h' }
      )

      global.logger.info(`Successful login: ${sanitizedEmail}`)

      // Match Juice Shop's original response shape so frontend still works
      res.json({
        authentication: {
          token,
          bid: user.id,
          umail: user.email
        }
      })

    } catch (err) {
      next(err)
    }
  }
}
