const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");

require("dotenv").config();

const authRoutes = require("./routes/auth");

const MONGODB_URI = process.env.DB_CONNECTION_STRING;
const PORT = process.env.PORT || 3000;

const app = express();

app.use(bodyParser.json());

// CORS Prevention Middleware for API
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, PATCH, DELETE"
  );
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  next();
});

app.use("/api/auth", authRoutes);

app.use((error, req, res, next) => {
  console.log(error);
  const status = error.statusCode || 500;
  const message = error.message;
  const data = error.data;
  res.status(status).json({ message: message, data: data });
});

mongoose
  .connect(MONGODB_URI)
  .then((result) => {
    app.listen(PORT, () => {
      console.log("<>-- Auth service is Listening to Port 3000 --<>");
    });
  })
  .catch((err) => {
    console.log(err);
  });

// reset token expiry time
