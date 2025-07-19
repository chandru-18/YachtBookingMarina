const mongoose = require('mongoose');

const bookingSchema = new mongoose.Schema({
  boat: String,
  date: String, // For best practice, use Date type and format in code
  hours: Number,
  persons: Number,
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});

module.exports = mongoose.model('Booking', bookingSchema);
