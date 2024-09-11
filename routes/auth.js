const express = require("express");
const { body } = require("express-validator");

const authController = require("../controllers/auth");
const isAuth = require("../middlewares/is-auth");

const router = express.Router();

router.post(
  "/register",
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

router.post("/refreshToken", authController.postRefreshToken);

router.post(
  "/requestPasswordReset",
  [
    body("email")
      .isEmail()
      .withMessage("Please enter a valid email")
      .normalizeEmail(),
  ],
  authController.postRequestPasswordReset
);

router.put(
  "/passwordReset",
  [
    body("newPassword").trim().isLength({ min: 5 }),
    body("confirmedNewPassword").trim().isLength({ min: 5 }),
  ],
  authController.putPasswordReset
);

router.put(
  "/changePassword",
  [
    body("newPassword").trim().isLength({ min: 5 }),
    body("confirmedPassword").trim().isLength({ min: 5 }),
  ],
  isAuth,
  authController.putChangePassword
);

router.post(
  "/requestVerifyEmail",
  [
    body("email")
      .isEmail()
      .withMessage("Please enter a valid email")
      .normalizeEmail(),
  ],
  authController.postRequestVerifyEmail
);

router.get("/verifyEmail", authController.getVerifyEmail);

router.post("/logout", isAuth, authController.postLogout);

router.get("/user", isAuth, authController.getUser);

router.delete(
  "/deleteUser",
  [body("password").trim().isLength({ min: 5 })],
  isAuth,
  authController.postDeleteAccount
);

module.exports = router;
