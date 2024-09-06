require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { validationResult } = require("express-validator");
const axios = require("axios");

const User = require("../models/user");

exports.postSignup = async (req, res, next) => {
  const verifyEmail = req.query.verifyEmail;

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

    if (verifyEmail === "true") {
      const resposne = await axios.post(
        "http://localhost:3000/api/auth/requestVerifyEmail",
        { email: email }
      );
      return res.status(201).json({
        message: "Created a New User and Requested Verification Email",
        userId: user._id,
      });
    }

    res.status(201).json({
      message: "Created a New User",
      userId: user._id,
    });
  } catch (err) {
    next(err);
  }
};

exports.postRequestVerifyEmail = async (req, res, next) => {
  const email = req.body.email;

  try {
    const user = await User.findOne({ email: email });
    if (!user) {
      const error = new Error("No such user");
      error.statusCode = 403;
      throw error;
    }

    const name = email.split("@")[0];

    const emailVerificationToken = jwt.sign(
      {
        email: email,
      },
      process.env.JWT_SECRET,
      { expiresIn: "6h" }
    );

    const verifyLink = `http://localhost:3000/api/auth/passwordReset?token=${emailVerificationToken}`;

    await axios.post("http://localhost:4000/api/mail/send-transactional", {
      recipient: {
        email: email,
        name: name,
      },
      subject: "Verify Your Email",
      templateId: 4,
      params: {
        verifyLink: verifyLink,
        userName: name,
        email: email,
      },
    });

    res.status(200).json({
      message: "Password reset email sent",
    });
  } catch (err) {
    next(err);
  }
};

exports.postVerifyEmail = async (req, res, next) => {
  const emailVerificationToken = req.query.token;

  try {
    if (!emailVerificationToken) {
      const error = new Error("No token provided");
      error.statusCode = 401;
      throw error;
    }

    let decodedToken;

    decodedToken = jwt.verify(emailVerificationToken, process.env.JWT_SECRET);

    if (!decodedToken) {
      const error = new Error("Not Authenticated");
      error.statusCode = 401;
      throw error;
    }

    const user = await User.findOne({ email: decodedToken.email });
    if (!user) {
      const error = new Error("No such user");
      error.statusCode = 404;
      throw error;
    }
    user.verified = true;
    await user.save();

    res.status(201).json({
      message: "Verified User Successfully",
    });
  } catch (err) {
    next(err);
  }
};

exports.postLogin = async (req, res, next) => {
  const verifyEmail = req.query.verifyEmail;

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
    if (verifyEmail === "true") {
      if (!user.verified) {
        const error = new Error("Your account is not verfied yet");
        error.statusCode = 403;
        throw error;
      }
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

    const refreshToken = jwt.sign(
      {
        email: user.email,
        userId: user._id.toString(),
      },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "7d" } // Refresh token valid for 7 days
    );

    user.refreshToken = refreshToken;

    await user.save();

    res.status(201).json({
      message: "Logged in user Successfully",
      userId: user._id.toString(),
      token: token,
      refreshToken: refreshToken,
      expiresIn: "8 hours",
    });
  } catch (err) {
    next(err);
  }
};

exports.postRefreshToken = async (req, res, next) => {
  const { refreshToken } = req.body;

  try {
    if (!refreshToken) {
      const error = new Error("Refresh token not provided.");
      error.statusCode = 422;
      throw error;
    }

    let decodedToken;

    decodedToken = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    if (!decodedToken) {
      const error = new Error("Refresh token not provided.");
      error.statusCode = 403;
      throw error;
    }

    const user = await User.findById(decodedToken.userId);
    if (!user || user.refreshToken !== refreshToken) {
      const error = new Error("Invalid refresh token.");
      error.statusCode = 403;
      throw error;
    }

    const newToken = jwt.sign(
      {
        email: user.email,
        userId: user._id.toString(),
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({
      token: newToken,
      expiresIn: "1 hour",
    });
  } catch (err) {
    next(err);
  }
};

exports.postRequestPasswordReset = async (req, res, next) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email: email });
    if (!user) {
      const error = new Error("No such user");
      error.statusCode = 403;
      throw error;
    }

    const name = email.split("@")[0];

    const passwordResetToken = jwt.sign(
      {
        email: email,
      },
      process.env.JWT_SECRET,
      { expiresIn: "20m" }
    );
    // Construct password reset link (with token)
    const resetLink = `http://localhost:3000/api/auth/passwordReset?token=${passwordResetToken}`;

    await axios.post(
      "http://localhost:4000/api/mail/send-transactional", // Call mail service to send the reset email
      {
        recipient: {
          email: email,
          name: name,
        },
        subject: "Reset Your Password",
        templateId: 3,
        params: {
          resetLink: resetLink,
          userName: name,
          email: email,
        },
      }
    );

    res.status(200).json({
      message: "Password reset email sent",
    });
  } catch (err) {
    next(err);
  }
};

exports.postPasswordReset = async (req, res, next) => {
  const passwordResetToken = req.query.token;
  const { newPassword, confirmedNewPassword } = req.body;

  try {
    if (!passwordResetToken) {
      const error = new Error("No token provided");
      error.statusCode = 401;
      throw error;
    }
    if (newPassword !== confirmedNewPassword) {
      const error = new Error("Passwords do not match");
      error.statusCode = 422;
      throw error;
    }
    let decodedToken;

    decodedToken = jwt.verify(passwordResetToken, process.env.JWT_SECRET);

    if (!decodedToken) {
      const error = new Error("Not Authenticated");
      error.statusCode = 401;
      throw error;
    }

    const user = await User.findOne({ email: decodedToken.email });
    if (!user) {
      const error = new Error("No such user");
      error.statusCode = 404;
      throw error;
    }
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    user.password = hashedPassword;
    await user.save();

    res.status(201).json({
      message: "Reset User Password Successfully",
    });
  } catch (err) {
    next(err);
  }
};

exports.putChangePassword = async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const error = new Error("Validation Failed");
    errors.statusCode = 422;
    errors.data = errors.array();
    return next(error);
  }
  const userId = req.userId;
  const oldPassword = req.body.oldPassword;
  const newPassword = req.body.newPassword;
  const confirmedPassword = req.body.confirmedPassword;

  try {
    const user = await User.findById(userId);
    if (!user) {
      const error = new Error("Unknown user");
      error.statusCode = 404;
      throw error;
    }
    if (newPassword !== confirmedPassword) {
      const error = new Error("Passwords do not match.");
      error.statusCode = 404;
      throw error;
    }
    const isEqual = await bcrypt.compare(oldPassword, user.password);
    if (!isEqual) {
      const error = new Error("Password is Incorrect.");
      error.statusCode = 422;
      throw error;
    }
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    user.password = hashedPassword;
    await user.save();

    res.status(201).json({
      message: "Changed password successfully",
      userId: userId,
    });
  } catch (err) {
    next(err);
  }
};

exports.postLogout = async (req, res, next) => {
  const { refreshToken } = req.body;

  try {
    if (!refreshToken) {
      const error = new Error("Refresh token not provided.");
      error.statusCode = 422;
      throw error;
    }

    let decodedToken;
    try {
      decodedToken = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch (err) {
      err.statusCode = 403;
      throw err;
    }

    const user = await User.findById(decodedToken.userId);
    if (!user) {
      const error = new Error("User not found.");
      error.statusCode = 404;
      throw error;
    }

    if (user.refreshToken !== refreshToken) {
      const error = new Error("Invalid refresh token.");
      error.statusCode = 403;
      throw error;
    }

    user.refreshToken = null;
    await user.save();

    res.status(200).json({ message: "User logged out successfully." });
  } catch (err) {
    next(err);
  }
};

exports.getUser = async (req, res, next) => {
  const userId = req.userId;
  try {
    user = await User.findById(userId);
    if (!user) {
      const error = new Error("User not found.");
      error.statusCode = 404;
      throw error;
    }
    res.status(200).json({
      message: "Fetched User info successfully",
      user: user,
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
