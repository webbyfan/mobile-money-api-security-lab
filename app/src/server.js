const express = require('express');
const mongoose = require('mongoose');

const app = express();
app.use(express.json());

app.get('/health', (req, res) => {
  const dbUp = mongoose.connection.readyState === 1;
  res.status(dbUp ? 200 : 503).json({ status: dbUp ? 'ok' : 'degraded', db: dbUp });
});

const port = process.env.PORT || 3000;

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => app.listen(port, '0.0.0.0', () => console.log(`listening on ${port}`)))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
