const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
  {
    phone: { type: String, unique: true },
    name: String,
    passwordHash: String,
    pin: String,                          // v1 flaw: PIN stored in plaintext
    role: { type: String, default: 'user' },
    balance: { type: Number, default: 1000 },
    webhookUrl: String,
  },
  { timestamps: true }
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
