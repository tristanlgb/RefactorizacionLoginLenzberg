const express = require('express');
const router = express.Router();
const passport = require('passport');
const authController = require('../controllers/authController');


router.post('/register', authController.register);


router.post('/login', passport.authenticate('local'), authController.login);


router.post('/logout', authController.logout);


router.get('/github', passport.authenticate('github', { scope: ['user:email'] }));
router.get('/github/callback', 
  passport.authenticate('github', { failureRedirect: '/' }),
  (req, res) => {
    res.redirect('/');
  }
);

module.exports = router;