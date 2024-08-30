const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { validationResult } = require("express-validator");

require("dotenv").config();

const User = require("../models/user");

exports.postSignup = async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const error = new Error("Validation Failed");
    errors.statusCode = 422;
    errors.data = errors.array();
    return next(error);
  }
  const email = req.body.email;
  const password = req.body.password;
  const confirmedPassword = req.body.confirmedPassword;
  try {
    if (!email || !password || !confirmedPassword) {
      const error = new Error("Complete info not provided.");
      error.statusCode = 422;
      throw error;
    }
    const checkUser = await User.findOne({ email: email });
    if (checkUser) {
      const error = new Error("User with this email already exists.");
      error.statusCode = 422;
      throw error;
    }
    if (password !== confirmedPassword) {
      const error = new Error("Passwords do not match.");
      error.statusCode = 422;
      throw error;
    }
    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({ email: email, password: hashedPassword });
    await user.save();

    res.status(201).json({
      message: "Created New User",
      user: user,
    });
  } catch (err) {
    next(err);
  }
};

exports.postLogin = async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const error = new Error("Validation Failed");
    errors.statusCode = 422;
    errors.data = errors.array();
    return next(error);
  }
  const email = req.body.email;
  const password = req.body.password;
  try {
    if (!email || !password) {
      const error = new Error("Complete info not provided.");
      error.statusCode = 422;
      throw error;
    }
    const user = await User.findOne({ email: email });
    if (!user) {
      const error = new Error("User with this email does not exists.");
      error.statusCode = 404;
      throw error;
    }
    const isEqual = await bcrypt.compare(password, user.password);
    if (!isEqual) {
      const error = new Error("Password is Incorrect.");
      error.statusCode = 422;
      throw error;
    }
    const token = jwt.sign(
      {
        email: user.email,
        userId: user._id.toString(),
      },
      process.env.JWT_SECRET,
      { expiresIn: "8h" }
    );

    res.status(201).json({
      message: "Logged in user Successfully",
      userId: user._id.toString(),
      token: token,
    });
  } catch (err) {
    next(err);
  }
};

exports.postDeleteAccount = async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const error = new Error("Validation Failed");
    errors.statusCode = 422;
    errors.data = errors.array();
    return next(error);
  }
  const userId = req.userId;
  const password = req.body.password;
  try {
    if (!password) {
      const error = new Error("Password not provided.");
      error.statusCode = 422;
      throw error;
    }
    const user = await User.findById(userId);
    if (!user) {
      const error = new Error("Unknown user");
      error.statusCode = 404;
      throw error;
    }
    const isEqual = await bcrypt.compare(password, user.password);
    if (!isEqual) {
      const error = new Error("Password is Incorrect.");
      error.statusCode = 422;
      throw error;
    }
    await User.findByIdAndDelete(userId);

    res.status(201).json({
      message: "Deleted user Successfully",
      userId: user._id.toString(),
    });
  } catch (err) {
    next(err);
  }
};
