const mongoose = require('mongoose');

const bookingSchema = new mongoose.Schema({
  boat: String,
  date: String, // for simplicity; in production, use type: Date
  hours: Number,
  persons: Number,
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});

module.exports = mongoose.model('Booking', bookingSchema);
