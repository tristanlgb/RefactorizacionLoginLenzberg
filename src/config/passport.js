const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const userDao = require('../daos/userDao');
const { comparePassword } = require('../utils/hash');

// Local strategy for username and password authentication
passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      const user = await userDao.findUserByUsername(username);
      if (!user) {
        return done(null, false, { message: 'Incorrect username.' });
      }
      const isValid = await comparePassword(password, user.password);
      if (!isValid) {
        return done(null, false, { message: 'Incorrect password.' });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

// GitHub strategy for GitHub authentication
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "http://localhost:8080/auth/github/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await userDao.findByGithubId(profile.id);
      if (!user) {
        user = await userDao.createUser({
          githubId: profile.id,
          username: profile.username
        });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await userDao.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

module.exports = passport;