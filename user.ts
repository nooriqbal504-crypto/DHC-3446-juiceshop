/*
 * DHC-3446 | Cybersecurity Internship 2026
 * models/user.ts — Patched User Model (forked from OWASP Juice Shop)
 *
 * VULNERABILITY FIXED: Plaintext Password Storage — "Encrypt the Vault"
 * ──────────────────────────────────────────────────────────────────────
 * ORIGINAL JUICE SHOP CODE (intentionally vulnerable):
 *   password: DataTypes.STRING  ← stored exactly as typed by the user
 *   A database breach reveals every user's real password immediately.
 *
 * OUR FIX (models/user.ts):
 *   - beforeCreate hook hashes every new password with bcrypt + random salt
 *   - beforeUpdate hook re-hashes if password field changes
 *   - Even if attacker reads the database, they only find gibberish like:
 *     $2b$12$3x8Kq... — impossible to reverse back to the real password
 */

import { DataTypes, Model, InferAttributes, InferCreationAttributes, CreationOptional } from 'sequelize'
import { sequelize } from './index'
import bcrypt from 'bcrypt'

const SALT_ROUNDS = 12

export class UserModel extends Model<InferAttributes<UserModel>, InferCreationAttributes<UserModel>> {
  declare id: CreationOptional<number>
  declare username: string | null
  declare email: string
  declare password: string        // Always stored as bcrypt hash — never plaintext
  declare role: CreationOptional<string>
  declare createdAt: CreationOptional<Date>
  declare updatedAt: CreationOptional<Date>
}

UserModel.init(
  {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    username: { type: DataTypes.STRING, allowNull: true },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      validate: { isEmail: true }   // DB-level email validation
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false
      // NOTE: Never queried as plaintext — always compared via bcrypt.compare()
    },
    role: { type: DataTypes.STRING, defaultValue: 'customer' },
    createdAt: DataTypes.DATE,
    updatedAt: DataTypes.DATE
  },
  {
    sequelize,
    tableName: 'Users',
    // THE FIX: bcrypt hook — runs automatically before every new user is saved
    hooks: {
      beforeCreate: async (user: UserModel) => {
        if (user.password) {
          // Hash + salt the password. SALT_ROUNDS=12 means ~300ms to compute —
          // makes brute-force attacks vastly more expensive.
          user.password = await bcrypt.hash(user.password, SALT_ROUNDS)
          global.logger.info(`Password hashed for new user: ${user.email}`)
        }
      },
      beforeUpdate: async (user: UserModel) => {
        // Re-hash only if the password field actually changed
        if (user.changed('password') && user.password) {
          user.password = await bcrypt.hash(user.password, SALT_ROUNDS)
          global.logger.info(`Password re-hashed on update for: ${user.email}`)
        }
      }
    }
  }
)
