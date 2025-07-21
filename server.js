require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const flash = require('connect-flash');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const methodOverride = require('method-override');

const app = express();
const PORT = process.env.PORT || 3000;

// ====== Models =======
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  resetToken: String,
  resetTokenExpires: Date
});
userSchema.pre('save', async function(next) {
  if (this.isModified('password')) this.password = await bcrypt.hash(this.password, 10);
  next();
});
const User = mongoose.model('User', userSchema);

const boatSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  display: String,
  maxPersons: { type: Number, required: true },
  pricePerHour: { type: Number, required: true },
  imageUrl: { type: String, default: '/images/default_boat.jpg' },
  availability: { type: Boolean, default: true }
});
const Boat = mongoose.model('Boat', boatSchema);

const bookingSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  boat: { type: mongoose.Schema.Types.ObjectId, ref: 'Boat', required: true },
  bookingDate: { type: Date, required: true },
  startTime: { type: String, required: true },
  endTime: { type: String, required: true },
  numberOfPersons: { type: Number, required: true },
  phoneNumber: { type: String, required: true },
  totalPrice: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'confirmed', 'cancelled', 'completed'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});
const Booking = mongoose.model('Booking', bookingSchema);

// ===== MongoDB ======
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log('MongoDB connected successfully');
    syncDefaultBoats();
  })
  .catch(err => console.error('MongoDB connection error:', err));

async function syncDefaultBoats() {
  const defaultBoats = [
    { name: "Luxury Cruiser", display: "Luxury Yacht", maxPersons: 10, pricePerHour: 500, imageUrl: "/images/luxury_cruiser.jpg" },
    { name: "Speedster 3000", display: "Speed Boat", maxPersons: 6, pricePerHour: 300, imageUrl: "/images/speedster.jpg" },
    { name: "Family Fun", display: "Pontoon Boat", maxPersons: 8, pricePerHour: 200, imageUrl: "/images/family_fun.jpg" },
    { name: "Sail Dream", display: "Sailboat", maxPersons: 4, pricePerHour: 250, imageUrl: "/images/sail_dream.jpg" }
  ];
  for (const boatData of defaultBoats) {
    await Boat.findOneAndUpdate(
      { name: boatData.name },
      { $set: boatData },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );
  }
  console.log('Default boats synced with database.');
}

// ===== Middleware Order =====
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(methodOverride('_method'));

// --- session FIRST, then flash, then res.locals ---
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
  cookie: { maxAge: 86400000 }
}));
app.use(flash());
app.use((req, res, next) => {
  res.locals.messages = req.flash();
  res.locals.user = req.session.user || null;
  next();
});
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ===== Email ======
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// ===== Auth Middleware =====
const isAuthenticated = (req, res, next) => {
  if (req.session.userId) return next();
  req.flash('error', 'Please log in to access this page.');
  res.redirect('/login');
};
const isAdmin = (req, res, next) => {
  if (req.session.user && req.session.user.isAdmin) return next();
  req.flash('error', 'Access denied. Administrator privileges required.');
  res.redirect('/');
};

// ===== Routes =====

// Home Page
app.get('/', async (req, res) => {
  try {
    const boats = await Boat.find({});
    res.render('index', { boats });
  } catch (error) {
    req.flash('error', 'Could not load boats.');
    res.render('index', { boats: [] });
  }
});

// User Registration
app.get('/register', (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (await User.findOne({ email })) {
      req.flash('error', 'Email already registered.');
      return res.redirect('/register');
    }
    const newUser = new User({ name, email, password });
    await newUser.save();
    req.flash('success', 'Registration successful! Please log in.');
    res.redirect('/login');
  } catch {
    req.flash('error', 'Registration failed.');
    res.redirect('/register');
  }
});

// Login/Logout
app.get('/login', (req, res) => res.render('login'));
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    req.flash('error', 'Invalid email or password.');
    return res.redirect('/login');
  }
  req.session.userId = user._id;
  req.session.user = { id: user._id, name: user.name, email: user.email, isAdmin: user.isAdmin };
  req.flash('success', 'Logged in successfully!');
  res.redirect('/dashboard');
});
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) console.log(err);
    res.clearCookie('connect.sid');
    req.flash('success', 'You have been logged out.');
    res.redirect('/login');
  });
});

// Forgot Password (/forgot)
app.get('/forgot', (req, res) => res.render('forgot'));
app.post('/forgot', async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      req.flash('error', 'No account with that email address exists.');
      return res.redirect('/forgot');
    }
    const resetToken = crypto.randomBytes(20).toString('hex');
    user.resetToken = resetToken;
    user.resetTokenExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    const resetUrl = `http://localhost:${PORT}/reset-password/${resetToken}`;
    await transporter.sendMail({
      to: user.email,
      from: process.env.EMAIL_USER,
      subject: 'Yacht Marina Booking - Password Reset',
      html: `<p>Click <a href="${resetUrl}">here</a> to reset your password. This link will expire in 1 hour.</p>`
    });

    req.flash('success', 'A password reset link has been sent to your email.');
    res.redirect('/forgot');
  } catch {
    req.flash('error', 'Could not send reset email. Try again.');
    res.redirect('/forgot');
  }
});
app.get('/reset-password/:token', async (req, res) => {
  try {
    const user = await User.findOne({
      resetToken: req.params.token,
      resetTokenExpires: { $gt: Date.now() }
    });
    if (!user) {
      req.flash('error', 'Token is invalid or expired.');
      return res.redirect('/forgot');
    }
    res.render('reset-password', { token: req.params.token });
  } catch {
    req.flash('error', 'Server error.');
    res.redirect('/forgot');
  }
});
app.post('/reset-password/:token', async (req, res) => {
  try {
    const user = await User.findOne({
      resetToken: req.params.token,
      resetTokenExpires: { $gt: Date.now() }
    });
    if (!user) {
      req.flash('error', 'Token is invalid or expired.');
      return res.redirect('/forgot');
    }
    if (req.body.password !== req.body.confirmPassword) {
      req.flash('error', 'Passwords do not match.');
      return res.redirect('/reset-password/' + req.params.token);
    }
    user.password = req.body.password;
    user.resetToken = undefined;
    user.resetTokenExpires = undefined;
    await user.save();
    req.flash('success', 'Your password has been updated!');
    res.redirect('/login');
  } catch {
    req.flash('error', 'Error resetting password.');
    res.redirect('/forgot');
  }
});

// User Dashboard (Safe)
app.get('/dashboard', isAuthenticated, async (req, res) => {
  try {
    const bookings = await Booking.find({ user: req.session.userId }).populate('boat');
    res.render('dashboard', {
      user: req.session.user,
      bookings: bookings
    });
  } catch (err) {
    req.flash('error', 'Unable to load dashboard.');
    res.redirect('/');
  }
});

// Bookings
app.get('/book/:boatId', isAuthenticated, async (req, res) => {
  const boat = await Boat.findById(req.params.boatId);
  if (!boat) {
    req.flash('error', 'Boat not found.');
    return res.redirect('/');
  }
  res.render('book', { boat });
});
app.post('/book', isAuthenticated, async (req, res) => {
  try {
    const { boatId, bookingDate, startTime, endTime, numberOfPersons, phoneNumber } = req.body;
    const boat = await Boat.findById(boatId);
    if (!boat) {
      req.flash('error', 'Boat not found for booking.');
      return res.redirect('/');
    }
    const startHour = parseInt(startTime.split(':')[0]);
    const endHour = parseInt(endTime.split(':')[0]);
    const durationHours = endHour - startHour;
    const totalPrice = durationHours * boat.pricePerHour;
    const newBooking = new Booking({
      user: req.session.userId,
      boat: boatId,
      bookingDate: new Date(bookingDate),
      startTime,
      endTime,
      numberOfPersons,
      phoneNumber,
      totalPrice
    });
    await newBooking.save();
    req.flash('success', 'Booking successful!');
    res.redirect('/bookings');
  } catch (error) {
    req.flash('error', 'Booking failed. Please try again.');
    res.redirect('/');
  }
});
app.get('/bookings', isAuthenticated, async (req, res) => {
  const bookings = await Booking.find({ user: req.session.userId }).populate('boat').sort({ bookingDate: 1, startTime: 1 });
  res.render('bookings', { bookings });
});

// Profile
app.get('/profile', isAuthenticated, (req, res) => {
  res.render('profile', { user: req.session.user });
});

// --- Admin ---

// /admin: redirect to dashboard
app.get('/admin', (req, res) => {
  res.redirect('/admin/dashboard');
});

// Admin Dashboard
app.get('/admin/dashboard', isAuthenticated, isAdmin, async (req, res) => {
  const users = await User.find({});
  const bookings = await Booking.find({}).populate('user').populate('boat').sort({ createdAt: -1 });
  res.render('admin/dashboard', { users, bookings });
});

// --- SERVER START ---
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
