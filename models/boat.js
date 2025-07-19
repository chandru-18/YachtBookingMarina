const mongoose = require('mongoose');

const boatSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  display: String,
  max: Number,
  price: Number,
  available: { type: Boolean, default: true }
});

module.exports = mongoose.model('Boat', boatSchema);
