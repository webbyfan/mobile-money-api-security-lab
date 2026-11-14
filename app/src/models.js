const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
  {
    phone: { type: String, unique: true },
    name: String,
    passwordHash: String,
    pinHash: String,                      // F-02 fix: PIN is now hashed, never stored plaintext
    role: { type: String, default: 'user' },
    balance: { type: Number, default: 1000 },
    webhookUrl: String,
  },
  {
    timestamps: true,
    toJSON: {
      transform: (doc, ret) => {
        delete ret.passwordHash;          // F-02 fix: strip sensitive fields from every response
        delete ret.pinHash;
        return ret;
      },
    },
  }
);

const txSchema = new mongoose.Schema(
  {
    from: mongoose.Schema.Types.ObjectId,
    to: mongoose.Schema.Types.ObjectId,
    amount: Number,
  },
  { timestamps: true }
);

module.exports = {
  User: mongoose.model('User', userSchema),
  Tx: mongoose.model('Tx', txSchema),
};
