const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const User = require('../models/userSchema');

passport.use(
  new LocalStrategy(
    {
      usernameField: 'email',
      passReqToCallback: true,
    },
    function (req, email, password, done) {
      // Find a user and establish the identity
      User.findOne({ email: email }, async function (err, user) {
        if (err) {
          req.flash('error', err.message);
          return done(err);
        }

        if (!user) {
          req.flash('error', 'Invalid Username or Password');
          return done(null, false);
        }

        // Match the password
        const isPasswordCorrect = await user.isValidatedPassword(password);

        if (!isPasswordCorrect) {
          req.flash('error', 'Invalid Username or Password');
          return done(null, false);
        }

        return done(null, user);
      });
    }
  )
);

//serialize user
passport.serializeUser(function (user, done) {
  done(null, user.id);
});

//deserialize user
passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    if (err) {
      console.log('Error in finding user--> Passport');
      return done(err);
    }
    return done(null, user);
  });
});

// check if user is authenticated
passport.checkAuthentication = function (req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  return res.redirect('/users/signin');
};

// set authenticated user for views
passport.setAuthenticatedUser = function (req, res, next) {
  if (req.isAuthenticated()) {
    res.locals.user = req.user;
  }
  next();
};
