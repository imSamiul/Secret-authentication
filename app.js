//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const app = express();
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const saltRounds = 10;
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});

const User = new mongoose.model("User", userSchema);
app.get("/", function (req, res) {
  res.render("Home");   
});
app.get("/login", function (req, res) {
  res.render("Login");
});
app.get("/register", function (req, res) {
  res.render("Register");
});
app.post("/register", function (req, res) {
  bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
    const newUser = new User({
      email: req.body.username,
      password: hash,
    });
    newUser.save(function (err) {
      if (!err) {
        res.render("secrets");
      } else {
        console.log(err);
      }
    });
  });
});
app.post("/login", function (req, res) {
  User.findOne({ email: req.body.username }, function (err, foundUser) {
    if (foundUser) {
        bcrypt.compare(req.body.password, foundUser.password, function(err, result) {
            if (result) {
              res.render("secrets");
            }
        });
      
    } else {
      console.log(err);
    }
  });
});
app.listen(3000, function () {
  console.log("Server Started at port 3000");
});
