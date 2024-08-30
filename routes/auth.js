const express = require("express");
const { body } = require("express-validator");

const authController = require("../controllers/auth");
const isAuth = require("../middlewares/is-auth");

const router = express.Router();

router.post(
  "/signup",
  [
    body("email")
      .isEmail()
      .withMessage("Please enter a valid email")
      .normalizeEmail(),
    body("password")
      .trim()
      .isLength({ min: 5 })
      .withMessage("Password must be at least 5 characters long"),
    body("confirmedPassword")
      .trim()
      .isLength({ min: 5 })
      .withMessage("Confirmed Password must be at least 5 characters long")
      .custom((value, { req }) => {
        if (value !== req.body.password) {
          throw new Error("Passwords do not match");
        }
        return true;
      }),
  ],
  authController.postSignup
);

router.post(
  "/login",
  [
    body("email")
      .isEmail()
      .withMessage("Please enter a valid email")
      .normalizeEmail(),
    body("password").trim().isLength({ min: 5 }),
  ],
  authController.postLogin
);

// router.put("/resetPassword");

router.delete(
  "/deleteUser",
  [body("password").trim().isLength({ min: 5 })],
  isAuth,
  authController.postDeleteAccount
);

module.exports = router;
