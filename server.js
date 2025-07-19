// Load environment variables
require('dotenv').config();

// Dependencies
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

// Express app
const app = express();
const PORT = 3000;

// Boat specs to sync on initial DB connect
const boatsArray = [
  { name: "Boat 1", display: "ORYX 46 ft (12-15) – 500 AED/hr", max: 15, price: 500, available: true },
  { name: "Boat 2", display: "Majesty 56 ft (20) – 800 AED/hr", max: 20, price: 800, available: true },
  { name: "Boat 3", display: "Fishing/Speed Boat 31 ft (10) – 349 AED/hr", max: 10, price: 349, available: true },
  { name: "Boat 4", display: "ORYX 36 ft (10) – 400 AED/hr", max: 10, price: 400, available: true }
];

// ✅ Connect MongoDB and Sync Boats
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
.then(async () => {
  console.log('✅ MongoDB Connected');

  // Sync default boats
  for (const b of boatsArray) {
    await Boat.updateOne(
      { name: b.name },
      { $setOnInsert: b },
      { upsert: true }
    );
  }

  // Create admin if not exists
  const adminEmail = "Admin@yachtmarina.com";
  const adminPassword = "PrinceAnthony@24";
  const existingAdmin = await User.findOne({ email: adminEmail });

  if (!existingAdmin) {
    const hash = await bcrypt.hash(adminPassword, 10);
    await User.create({
      name: 'Yacht Admin',
      email: adminEmail,
      password: hash,
      isAdmin: true
    });
    console.log('✅ Default Admin Created → Email: Admin@yachtmarina.com');
  }

  console.log('✅ Boats Synced. Ready to Sail ⛵');
})
.catch((err) => {
  console.error('❌ MongoDB Connection Error:', err.message);
});

// View Engine & Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

// Sessions + Flash
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

// 🌐 ROUTES

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
    await User.create({
      name: req.body.name,
      email: req.body.email,
      password: hash
    });
    req.flash("success", "Registration successful! Please login.");
    res.redirect('/login');
  } catch (err) {
    req.flash("error", "Email already exists.");
    res.redirect('/register');
  }
});

// Login / Logout
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

// Booking
app.post('/book', ensureAuth, async (req, res) => {
  await Booking.create({
    boat: req.body.boat,
    date: req.body.date,
    hours: req.body.hours,
    persons: req.body.persons,
    user: req.session.userId
  });
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
    {
      boat: req.body.boat,
      date: req.body.date,
      hours: req.body.hours,
      persons: req.body.persons
    }
  );
  req.flash("success", "✅ Booking updated");
  res.redirect('/admin');
});

// 404
app.use((req, res) => {
  res.status(404).send('<h2>404 - Page Not Found</h2>');
});

app.listen(PORT, () => {
  console.log(`🌐 Server running at http://localhost:${PORT}`);
});
