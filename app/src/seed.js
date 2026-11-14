const mongoose = require('mongoose');
const { User, Tx } = require('./models');
const { hash } = require('./util');

(async () => {
  await mongoose.connect(process.env.MONGO_URI);
  await User.deleteMany({});
  await Tx.deleteMany({});
  await User.create([
    { phone: '0911000001', name: 'Alice', pinHash: hash('1234'), passwordHash: hash('alice-pass'), balance: 1000 },
    { phone: '0911000002', name: 'Bob', pinHash: hash('4321'), passwordHash: hash('bob-pass'), balance: 1000 },
    { phone: '0911000099', name: 'Admin', pinHash: hash('9999'), passwordHash: hash('admin-pass'), role: 'admin', balance: 0 },
  ]);
  console.log('seeded');
  await mongoose.disconnect();
})();
