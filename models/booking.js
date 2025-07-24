const mongoose = require('mongoose');

const bookingSchema = new mongoose.Schema({
  boat: { type: mongoose.Schema.Types.ObjectId, ref: 'Boat', required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  bookingDate: { type: Date, required: true },
  startTime: { type: String, required: true },
  endTime: { type: String, required: true },
  numberOfPersons: { type: Number, required: true },
  phoneNumber: { type: String, required: true },
  totalPrice: { type: Number, required: true },
  status: {
    type: String,
    enum: ['pending', 'confirmed', 'cancelled', 'completed'],
    default: 'pending'
  },
  createdAt: { type: Date, default: Date.now }
});


bookingSchema.pre('save', function(next) {
  let num = this.phoneNumber ? this.phoneNumber.trim() : '';
  num = num.replace(/[\s\-()]/g, '');
  if (num.startsWith('00')) {
    num = '+' + num.slice(2);
  }
  if (!num.startsWith('+')) {
    if (num.length === 10 && num.startsWith('0')) {
      num = '+971' + num.slice(1); // Change to +91 for India if you want
    } else if (num.length >= 8 && /^\d+$/.test(num)) {
      num = '+971' + num;
    } else {
      num = '+' + num;
    }
  }
  this.phoneNumber = num;
  next();
});

module.exports = mongoose.model('Booking', bookingSchema);
