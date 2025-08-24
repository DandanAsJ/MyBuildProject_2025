'use strict';
const { Model } = require('sequelize');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');


const BCRYPT_ROUNDS = 12;

module.exports = (sequelize, DataTypes) => {
  class User extends Model {
    static associate(models) {
      // e.g., Customer.hasMany(models.PasswordItem, { foreignKey: 'customer_id' });
    }


    // Static method to verify JWT token
    static async verifyToken(token) {
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findByPk(decoded.user_id);
        if (!user) throw new Error('User not found');
        return user;
      } catch (error) {
        throw new Error('Invalid token');
      }
    }
  }


  User.init(
    {
      name: {
        type: DataTypes.STRING(100),
        allowNull: false,
        validate: {
          notEmpty: { msg: 'Name is required' },
          len: { args: [2, 100], msg: 'Name must be between 2 and 100 characters' },
          isValidName(value) {
            const re = /^[\p{L}\p{N}\s.'-]+$/u; // letters/numbers/spaces/'/./-
            if (!re.test(value)) throw new Error('Name has invalid characters');
          },
        },
      },

      email: {
        type: DataTypes.STRING(255),
        allowNull: false,
        unique: true,
        set(value) {
          this.setDataValue(
            'email',
            typeof value === 'string' ? value.trim().toLowerCase() : value
          );
        },
        validate: {
          notEmpty: { msg: 'Email is required' },
          isEmail: { msg: 'Please enter a valid email address' },
          len: { args: [3, 255], msg: 'Email is too long' },
        },
      },

      // Virtual input at signup/update
      password: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: {
          len: {
            args: [8, 200],
            msg: 'Password must be between 8 and 200 characters',
          },
          isStrongPassword(value) {
            if (value == null) return;
            const strong = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
            if (!strong.test(value)) {
              throw new Error(
                'Password must contain at least one uppercase, one lowercase, one number, and one special character'
              );
            }
          },
        },
      },
      // Virtual input for vault key (client uses it to encrypt; server stores only a verifier)
      encryption_key: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: {
          len: {
            args: [8, 200],
            msg: 'Encryption key must be between 8 and 200 characters',
          },
        },
      },


    }, {
    sequelize,
    modelName: 'User',
    tableName: 'users',
    underscored: false,

    hooks: {
      beforeCreate: async (user, options) => {
        // You can hash password or encryption_key here
      },
      beforeUpdate: async (user, options) => {
        // Re-hash if needed
      }
    },
  }
  );

  return User;
};
