const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../models/User');

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: '/api/auth/google/callback',
      scope: ['profile', 'email'],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Find a user by their Google ID
        let user = await User.findOne({ googleId: profile.id });

        if (user) {
          // If user exists, pass them to the next middleware
          return done(null, user);
        }

        // If no user with that Google ID, check for an existing user with the same email
        const googleEmail = profile.emails[0].value;
        user = await User.findOne({ email: googleEmail });

        if (user) {
          // If a user with that email exists, link their Google account
          user.googleId = profile.id;
          user.profilePicture = user.profilePicture || profile.photos[0].value;
          user.emailVerified = true; 
          await user.save();
          return done(null, user);
        }

        // If no user exists at all, create a new one
        const newUser = await User.create({
          googleId: profile.id,
          email: googleEmail,
          name: profile.displayName,
          givenName: profile.name.givenName,
          familyName: profile.name.familyName,
          profilePicture: profile.photos[0].value,
          emailVerified: true,
          roles: ['user'],
        });

        return done(null, newUser);
      } catch (err) {
        return done(err, false, { message: 'Authentication failed.' });
      }
    }
  )
);