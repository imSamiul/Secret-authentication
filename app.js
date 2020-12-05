//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const app = express();
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

//setup session(package)
app.use(
  session({
    // telling our app to use "session" package.
    secret: "Our little Secret.", // keep secret in our environment file.
    resave: false,
    saveUninitialized: false,
  })
);

//Initialize Passport(http://www.passportjs.org/docs/configure/)
app.use(passport.initialize()); //This is a method that comes bundled with passport and sets up passport for us to start using it for authintication.
app.use(passport.session()); //Telling our app to use passport to also set up our session.

mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
app.set("view engine", "ejs");
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});

//useing Passport-Local-Mongoose as Mongoose Schema plugin
userSchema.plugin(passportLocalMongoose); //"passportLocalMongoose" used to hash and salt password and save user into MongoDB database.

const User = new mongoose.model("User", userSchema);

//Passport-Local-Mongoose configuration. Create local login straegy.
passport.use(User.createStrategy()); //Local strategy to authenticate user using their username and password.
//serialize and deserialize is only necessary when using session.
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/", function (req, res) {
  res.render("Home");
});
app.get("/login", function (req, res) {
  res.render("Login");
});
app.get("/register", function (req, res) {
  res.render("Register");
});
app.get("/secrets", function (req, res) {
  //Checking if the user is authenticatd or not , relying on "Passport", "Session", "Passport-Local", "Passport-Local-Mongoose".
  //to make sure that if the user is already logged in then we should render in the "Secrets" page.
  //if they are not logged in then we redirect them to the "Login" Page.

  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
});
app.get("/logout",function (req, res) {
  //de-authenticate user and end user session. (http://www.passportjs.org/docs/logout/)
  req.logout();
  res.redirect("/")
}); 
app.post("/register", function (req, res) {
  //Using Passport-Local-Mongoose package to register user. (https://www.npmjs.com/package/passport-local-mongoose)
  User.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        //Authenticating user using Passport.
        passport.authenticate("local")(req, res, function () {
          //This callback will only tigered if the authentication is successfull and we manage to successfully setup a cookie that saved their current logged in sessions.
          //so we will have to check to see if they are logged in or not.
          res.redirect("/secrets");
        });
      }
    }
  );
});
app.post("/login", function (req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });
  //Using Passport to login this user and authenticate them.
  //(http://www.passportjs.org/docs/login/)
  //Using login method from passport.
  req.login(user, function (err) {
    //passing new User
    if (err) {
      console.log(err);
    } else {
      //Authenticating the user.
      passport.authenticate("local")(req, res, function () {
        //this will authenticate user using their password and username.
        res.redirect("/secrets");
      });
    }
  });
});
app.listen(3000, function () {
  console.log("Server Started at port 3000");
});
