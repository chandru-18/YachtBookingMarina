require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const flash = require('connect-flash');
const path = require('path');
const User = require('./models/user');
const Boat = require('./models/boat');
const Booking = require('./models/booking');
const { format } = require('@fast-csv/format');
const PDFDocument = require('pdfkit');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

// Express & Socket
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);
app.set('socketio', io);
const PORT = 3000;

// Boat specs to sync with DB
const boatsArray = [
  { name: "Boat 1", display: "ORYX 46 ft (12-15) – 500 AED/hr", max: 15, price: 500, available: true },
  { name: "Boat 2", display: "Majesty 56 ft (20) – 800 AED/hr", max: 20, price: 800, available: true },
  { name: "Boat 3", display: "Fishing/Speed Boat 31 ft (10) – 349 AED/hr", max: 10, price: 349, available: true },
  { name: "Boat 4", display: "ORYX 36 ft (10) – 400 AED/hr", max: 10, price: 400, available: true }
];

// Connect MongoDB and Sync Boats
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(async () => {
    console.log('✅ MongoDB Connected');
    // Sync default boats
    for (const b of boatsArray) {
      await Boat.updateOne({ name: b.name }, { $setOnInsert: b }, { upsert: true });
    }
    // Create default admin
    const adminEmail = "Admin@yachtmarina.com";
    const adminPassword = "PrinceAnthony@24";
    const existingAdmin = await User.findOne({ email: adminEmail });
    if (!existingAdmin) {
      const hash = await bcrypt.hash(adminPassword, 10);
      await User.create({ name: 'Yacht Admin', email: adminEmail, password: hash, isAdmin: true });
      console.log('✅ Default Admin Created → Email: Admin@yachtmarina.com');
    }
    console.log('✅ Boats Synced.');
  })
  .catch((err) => {
    console.error('❌ MongoDB Connection Error:', err.message);
  });

// View Engine & Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'backupsecret',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URI })
}));
app.use(flash());
app.use((req, res, next) => {
  res.locals.success = req.flash("success");
  res.locals.error = req.flash("error");
  res.locals.user = req.session.user;
  next();
});

// Auth Middleware
function ensureAuth(req, res, next) {
  if (req.session.userId) return next();
  return res.redirect('/login');
}
function ensureGuest(req, res, next) {
  if (!req.session.userId) return next();
  return res.redirect('/dashboard');
}

// Home
app.get('/', async (req, res) => {
  const boats = await Boat.find({ available: true });
  res.render('index', { boats });
});

// Register
app.get('/register', ensureGuest, (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
  try {
    const hash = await bcrypt.hash(req.body.password, 10);
    await User.create({ name: req.body.name, email: req.body.email, password: hash });
    req.flash("success", "Registration successful! Please login.");
    res.redirect('/login');
  } catch (err) {
    req.flash("error", "Email already exists.");
    res.redirect('/register');
  }
});

// Login/Logout
app.get('/login', ensureGuest, (req, res) => res.render('login'));
app.post('/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (user && await bcrypt.compare(req.body.password, user.password)) {
    req.session.userId = user._id;
    req.session.user = user;
    res.redirect('/dashboard');
  } else {
    req.flash("error", "Invalid login details");
    res.redirect('/login');
  }
});
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// Forgot Password (Request Mail)
app.get('/forgot', ensureGuest, (req, res) => res.render('forgot'));
app.post('/forgot', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    req.flash('error', 'User not found');
    return res.redirect('/forgot');
  }
  const token = crypto.randomBytes(32).toString('hex');
  user.resetToken = token;
  user.resetTokenExpires = Date.now() + 3600000;
  await user.save();
  const resetLink = `http://localhost:${PORT}/reset/${token}`;
  const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: { user: process.env.EMAIL, pass: process.env.PASSWORD }
  });
  await transporter.sendMail({
    to: user.email,
    subject: 'Password Reset - Yacht Booking',
    html: `<p>Click <a href="${resetLink}">here</a> to reset your password.</p>`
  });
  req.flash('success', 'Reset link sent to email');
  res.redirect('/login');
});
app.get('/reset/:token', (req, res) => res.render('reset-password', { token: req.params.token }));
app.post('/reset/:token', async (req, res) => {
  const user = await User.findOne({
    resetToken: req.params.token,
    resetTokenExpires: { $gt: Date.now() }
  });
  if (!user) {
    req.flash('error', 'Reset link expired');
    return res.redirect('/login');
  }
  const hashed = await bcrypt.hash(req.body.password, 10);
  user.password = hashed;
  user.resetToken = undefined;
  user.resetTokenExpires = undefined;
  await user.save();
  req.flash('success', 'Password updated');
  res.redirect('/login');
});

// Booking
app.post('/book', ensureAuth, async (req, res) => {
  const user = await User.findById(req.session.userId);
  const booking = await Booking.create({
    boat: req.body.boat,
    date: req.body.date,
    hours: req.body.hours,
    persons: req.body.persons,
    user: req.session.userId
  });
  // Send mail
  const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: { user: process.env.EMAIL, pass: process.env.PASSWORD }
  });
  await transporter.sendMail({
    to: user.email,
    subject: 'Booking Confirmation',
    html: `<p>Thanks for booking <strong>${req.body.boat}</strong> on ${req.body.date} for ${req.body.hours} hours.</p>`
  });
  // Emit admin notification (Socket.IO)
  const io = req.app.get('socketio');
  io.emit('newBooking', { boat: req.body.boat, date: req.body.date, user: user.name });

  req.flash("success", "✅ Booking confirmed!");
  res.redirect('/dashboard');
});

// Dashboard
app.get('/dashboard', ensureAuth, async (req, res) => {
  const bookings = await Booking.find({ user: req.session.userId });
  res.render('dashboard', { bookings });
});

// Admin Panel
app.get('/admin', ensureAuth, async (req, res) => {
  if (!req.session.user.isAdmin) return res.send('Access Denied');
  const boats = await Boat.find();
  const bookings = await Booking.find().populate('user');
  res.render('admin', { bookings, boats });
});
app.post('/admin/update-boats', ensureAuth, async (req, res) => {
  if (!req.session.user.isAdmin) return res.send('Access Denied');
  const boats = await Boat.find();
  for (let boat of boats) {
    const available = req.body[boat.name] === 'on';
    await Boat.updateOne({ name: boat.name }, { available });
  }
  req.flash("success", "✅ Boat availability updated");
  res.redirect('/admin');
});

// CSV Export
app.get('/admin/export/csv', ensureAuth, async (req, res) => {
  if (!req.session.user.isAdmin) return res.send('Access Denied');
  const bookings = await Booking.find().populate('user');
  res.setHeader('Content-Disposition', 'attachment; filename=bookings.csv');
  res.setHeader('Content-Type', 'text/csv');
  const csv = format({ headers: true });
  csv.pipe(res);
  bookings.forEach(b => {
    csv.write({
      Boat: b.boat,
      Date: b.date,
      Hours: b.hours,
      Persons: b.persons,
      User: b.user?.name,
      Email: b.user?.email
    });
  });
  csv.end();
});

// PDF Export
app.get('/admin/export/pdf', ensureAuth, async (req, res) => {
  if (!req.session.user.isAdmin) return res.send('Access Denied');
  const bookings = await Booking.find().populate('user');
  res.setHeader('Content-Disposition', 'attachment; filename=bookings.pdf');
  res.setHeader('Content-Type', 'application/pdf');
  const doc = new PDFDocument();
  doc.pipe(res);
  doc.fontSize(20).text('📋 Booking Records', { align: 'center' }).moveDown();
  bookings.forEach((b, i) => {
    doc.fontSize(12).text(`${i + 1}. 🛥 Boat: ${b.boat}, 📅 Date: ${b.date}, ⏱ Hours: ${b.hours}, 👥 Persons: ${b.persons}, 👤 User: ${b.user?.name} (${b.user?.email})`);
  });
  doc.end();
});

// Booking Edit/Delete
app.post('/admin/delete-booking/:id', ensureAuth, async (req, res) => {
  if (!req.session.user.isAdmin) return res.send('Access Denied');
  await Booking.deleteOne({ _id: req.params.id });
  req.flash("success", "✅ Booking deleted");
  res.redirect('/admin');
});
app.get('/admin/edit-booking/:id', ensureAuth, async (req, res) => {
  if (!req.session.user.isAdmin) return res.send('Access Denied');
  const booking = await Booking.findById(req.params.id).populate('user');
  const boats = await Boat.find();
  res.render('edit-booking', { booking, boats });
});
app.post('/admin/edit-booking/:id', ensureAuth, async (req, res) => {
  if (!req.session.user.isAdmin) return res.send('Access Denied');
  await Booking.updateOne(
    { _id: req.params.id },
    { boat: req.body.boat, date: req.body.date, hours: req.body.hours, persons: req.body.persons }
  );
  req.flash("success", "✅ Booking updated");
  res.redirect('/admin');
});

// Forgotten Password UI
app.get('/forgot', ensureGuest, (req, res) => res.render('forgot'));

// 404
app.use((req, res) => {
  res.status(404).send('Page Not Found');
});

http.listen(PORT, () => {
  console.log(`🚢 Yacht Booking server running on http://localhost:${PORT}`);
});
