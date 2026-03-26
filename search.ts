/*
 * DHC-3446 | Cybersecurity Internship 2026
 * routes/search.ts — Patched Search Route (forked from OWASP Juice Shop)
 *
 * VULNERABILITY FIXED: Reflected XSS — "The Script Injection"
 * ─────────────────────────────────────────────────────────────
 * ORIGINAL JUICE SHOP CODE (intentionally vulnerable):
 *   res.json({ data: await models.sequelize.query(
 *     `SELECT ... WHERE name LIKE '%${req.query.q}%' OR description LIKE '%${req.query.q}%'`
 *   )})
 *   The raw query value also gets reflected into HTML responses without escaping.
 *
 *   Attack: q=<iframe src="javascript:alert('XSS')">
 *   → Browser receives and executes the script → session cookie theft.
 *
 * OUR FIX:
 *   - validator.escape() converts < > " ' & into safe HTML entities
 *   - Malicious <iframe> tag renders as harmless visible text, never executes
 *   - Sequelize LIKE query uses the escaped value — parameterized, not interpolated
 */

import { Request, Response, NextFunction } from 'express'
import validator from 'validator'
import { ProductModel } from '../models/product'
import { Op } from 'sequelize'

export function search () {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const rawQuery = req.query.q

      if (!rawQuery || typeof rawQuery !== 'string') {
        res.status(400).json({ error: 'Search query is required' })
        return
      }

      // THE FIX: validator.escape() neutralizes all XSS characters
      // <iframe src="javascript:alert('XSS')"> becomes:
      // &lt;iframe src=&quot;javascript:alert(&#x27;XSS&#x27;)&quot;&gt;
      // → Browser prints it as plain text. Script never runs.
      const safeQuery = validator.escape(rawQuery.trim())

      global.logger.info(`Search performed — query: "${safeQuery}"`)

      // Parameterized LIKE query — safe from SQL injection too
      const results = await ProductModel.findAll({
        where: {
          [Op.or]: [
            { name: { [Op.like]: `%${safeQuery}%` } },
            { description: { [Op.like]: `%${safeQuery}%` } }
          ]
        }
      })

      res.json({ status: 'success', data: results })

    } catch (err) {
      next(err)
    }
  }
}
