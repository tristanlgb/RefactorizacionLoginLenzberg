const { hashPassword, comparePassword } = require('../utils/hash');
const userDao = require('../daos/userDao');
const passport = require('passport');

const register = async (req, res) => {
  const { username, password } = req.body;
  const existingUser = await userDao.findUserByUsername(username);
  if (existingUser) {
    return res.status(400).json({ message: 'Username already taken' });
  }

  const hashedPassword = await hashPassword(password);
  const newUser = await userDao.createUser({ username, password: hashedPassword });
  return res.status(201).json({ message: 'User created', user: newUser });
};

const login = (req, res) => {
  res.status(200).json({ message: 'Logged in successfully' });
};

const logout = (req, res) => {
  req.logout(err => {
    if (err) return next(err);
    res.status(200).json({ message: 'Logged out successfully' });
  });
};

module.exports = { register, login, logout };