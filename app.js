const path = require('path');
const express = require('express');
const compression = require('compression');
const session = require('express-session');
const bodyParser = require('body-parser');
const logger = require('morgan');
const errorHandler = require('errorhandler');
const lusca = require('lusca');
const dotenv = require('dotenv');
const MongoStore = require('connect-mongo');
const flash = require('express-flash');
const mongoose = require('mongoose');
const passport = require('passport');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const { createServer } = require('http');
const { Server } = require('socket.io');

const upload = multer({ dest: path.join(__dirname, 'uploads') });


dotenv.config({ path: '.env' });


const secureTransfer = process.env.VERCEL_URL ? true : (process.env.NODE_ENV === 'production');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests, please try again later.',
  skip: (req) => {
    return req.path.startsWith('/api/chat/') || 
           req.path.startsWith('/chat') ||
           req.path === '/socket.io/';
  }
});

const chatLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many chat requests, please try again later.'
});

let numberOfProxies;
if (secureTransfer) numberOfProxies = 1; else numberOfProxies = 0;

/**
 * Controllers 
 */
const homeController = require('./controllers/home');
const userController = require('./controllers/user');
const chatController = require('./controllers/chatController');
const donorController = require('./controllers/donorController');

/**
 * API keys and Passport configuration.
 */
const passportConfig = require('./config/passport');

/**
 * Create Express server.
 */
const app = express();
console.log('Run this app using "npm start" to include sass/scss/css builds.\n');

/**
 * Socket.io setup
 */
const server = createServer(app);

// Initialize socket.io only in non-Vercel environment
if (!process.env.VERCEL) {
  const { initializeChat } = require('./chat');
  initializeChat(server);
}

/**
 * Connect to MongoDB.
 */
let cachedDb = null;

const connectDB = async () => {
  if (cachedDb) {
    console.log('Using cached database connection');
    return;
  }

  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 30000,
      socketTimeoutMS: 60000,
      family: 4,
      retryWrites: true,
      w: 'majority'
    });
    
    cachedDb = mongoose.connection;
    console.log('MongoDB connected successfully');
  } catch (err) {
    console.error('MongoDB connection error:', err);
    cachedDb = null;
    if (!process.env.VERCEL) {
      process.exit(1);
    }
  }
};

// Connect to MongoDB
connectDB();

mongoose.connection.on('connected', () => {
  console.log('MongoDB connected successfully');
});

mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
  console.log('Please make sure MongoDB is running and accessible');
  process.exit(1);
});

mongoose.connection.on('disconnected', () => {
  console.log('MongoDB disconnected');
});

/**
 * Express configuration.
 */
app.set('port', process.env.PORT || 3000);
app.enable('trust proxy');
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');
app.set('trust proxy', 1);
app.use(compression());
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Apply rate limiting after body parsing but before session
app.use(limiter);
app.use(session({
  resave: false,
  saveUninitialized: false,
  secret: process.env.SESSION_SECRET,
  name: 'startercookie',
  cookie: {
    maxAge: 1209600000, // 14 days
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    domain: process.env.VERCEL_URL ? `.${process.env.VERCEL_URL}` : undefined
  },
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    autoRemove: 'interval',
    autoRemoveInterval: 60, // Check expired sessions every hour
    ttl: 14 * 24 * 60 * 60, // 14 days
    touchAfter: 24 * 3600 // Only update session every 24 hours unless data changes
  })
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// Make Flash Messages available to all views
app.use((req, res, next) => {
  res.locals.messages = req.flash();
  next();
});

// Environment middleware - make env variables available to all views
app.use((req, res, next) => {
  res.locals.env = {
    NODE_ENV: process.env.NODE_ENV || 'development',
    isProduction: process.env.NODE_ENV === 'production'
  };
  next();
});

// Initialize CSRF protection
app.use(lusca({
  csrf: true,
  xframe: 'SAMEORIGIN',
  xssProtection: true
}));

// Make user and CSRF token available to views
app.use((req, res, next) => {
  // Skip CSRF for API routes
  if (req.path.startsWith('/api/')) {
    return next();
  }

  res.locals.user = req.user;
  // Generate CSRF token
  res.locals._csrf = req.csrfToken();
  next();
});

// Skip CSRF for specific routes
app.use((req, res, next) => {
  if (req.path === '/socket.io/' || req.path.startsWith('/api/chat/')) {
    return next();
  }
  lusca.csrf()(req, res, next);
});

app.use((req, res, next) => {
  if (!req.user && req.path !== '/login' && req.path !== '/signup' && !req.path.match(/\./)) {
    req.session.returnTo = req.originalUrl;
  }
  next();
});

app.use('/', express.static(path.join(__dirname, 'public'), { 
  maxAge: 31557600000,
  etag: true,
  lastModified: true
}));
app.use('/js/lib', express.static(path.join(__dirname, 'node_modules/bootstrap/dist/js'), { maxAge: 31557600000 }));
app.use('/js/lib', express.static(path.join(__dirname, 'node_modules/jquery/dist'), { maxAge: 31557600000 }));
app.use('/webfonts', express.static(path.join(__dirname, 'node_modules/@fortawesome/fontawesome-free/webfonts'), { maxAge: 31557600000 }));

/**
 * Primary app routes.
 */
app.get('/', homeController.index);
app.get('/messages', passportConfig.isAuthenticated, (req, res) => {
  res.render('messages', {
    title: 'Messages'
  });
});
app.get('/chat', passportConfig.isAuthenticated, (req, res) => {
  const userId = req.query.userId;
  res.render('chat', {
    title: 'Chat',
    targetUserId: userId
  });
});
app.get('/login', userController.getLogin);
app.post('/login', userController.postLogin);
app.get('/logout', userController.logout);
app.get('/signup', userController.getSignup);
app.post('/signup', userController.postSignup);
app.get('/account', passportConfig.isAuthenticated, userController.getAccount);
app.post('/account/profile', passportConfig.isAuthenticated, userController.postUpdateProfile);
app.post('/account/password', passportConfig.isAuthenticated, userController.postUpdatePassword);
app.get('/donors', donorController.getDonors);
app.get('/about', (req, res) => {
  res.render('about', {
    title: 'About Us'
  });
});

// Chat routes
app.get('/api/chat/conversations', passportConfig.isAuthenticated, chatController.getConversations);
app.get('/api/chat/history/:otherUserId', passportConfig.isAuthenticated, chatController.getChatHistory);
app.post('/api/chat/mark-read/:otherUserId', passportConfig.isAuthenticated, chatController.markAsRead);
app.get('/api/user/:id', passportConfig.isAuthenticated, userController.getUserInfo);

/**
 * Error Handler.
 */
app.use((req, res, next) => {
  const err = new Error('Not Found');
  err.status = 404;
  res.status(404).send('Page Not Found');
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error Details:', {
    message: err.message,
    stack: err.stack,
    code: err.code,
    name: err.name
  });
  
  // Handle mongoose validation errors
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map(e => ({ msg: e.message }));
    if (req.xhr || /^\/api\//.test(req.path)) {
      return res.status(400).json({ errors });
    }
    req.flash('errors', errors);
    return res.redirect('back');
  }

  // Handle unique constraint errors
  if (err.code === 11000) {
    if (req.xhr || /^\/api\//.test(req.path)) {
      return res.status(400).json({ error: 'That email address is already in use.' });
    }
    req.flash('errors', [{ msg: 'That email address is already in use.' }]);
    return res.redirect('back');
  }

  const status = err.status || 500;
  const errorResponse = {
    title: `Error ${status}`,
    message: err.message || 'An error occurred',
    error: process.env.NODE_ENV === 'development' ? err : {},
    status: status
  };

  // Log detailed error for debugging in production
  if (process.env.NODE_ENV === 'production') {
    console.error('Production Error:', {
      ...errorResponse,
      stack: err.stack,
      originalError: err
    });
  }

  if (req.xhr || /^\/api\//.test(req.path)) {
    return res.status(status).json({
      error: process.env.NODE_ENV === 'development' ? errorResponse : 'An error occurred'
    });
  }

  res.status(status);
  res.render('error', errorResponse);
});

// Apply chat-specific rate limiter to chat routes
app.use('/api/chat', chatLimiter);
app.use('/chat', chatLimiter);

/**
 * Start Express server.
 */
if (process.env.VERCEL) {
  // For Vercel serverless deployment
  module.exports = app;

  // Handle unhandled promise rejections
  process.on('unhandledRejection', (err) => {
    console.error('Unhandled Rejection:', err);
  });

  // Handle uncaught exceptions
  process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
  });
} else {
  // Start the server for local development
  server.listen(app.get('port'), () => {
    console.log(`App is running on port ${app.get('port')} in ${app.get('env')} mode.`);
    console.log('Press CTRL-C to stop.');
  });
}

module.exports = server;
