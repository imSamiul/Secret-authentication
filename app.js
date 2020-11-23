//jshint esversion:6
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const app = express();
const mongoose = require('mongoose')
const encrypt = require('mongoose-encryption');
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
mongoose.connect('mongodb://localhost:27017/userDB', {useNewUrlParser: true, useUnifiedTopology: true});
const userSchema = new mongoose.Schema ({
    email: String,
    password: String
  });

const secret = "This is my secret string.";
//add this plugin with Schema before model.
userSchema.plugin(encrypt, {secret: secret, encryptedFields: ["password"]});
  
const User = new mongoose.model('User', userSchema);
app.get("/", function(req, res) {
    res.render("Home");
});
app.get("/login", function(req, res) {
    res.render("Login");
});
app.get("/register", function(req, res) {
    res.render("Register");
});
app.post("/register", function (req, res) {
    const newUser = new User({
        email: req.body.username,
        password: req.body.password
    });
    newUser.save(function(err) {
        if (!err) {
            res.render("secrets");
        }
        else{
            console.log(err);
        }
    });
});
app.post("/login", function(req, res){
    User.findOne({email: req.body.username}, function(err, foundUser){
        console.log(foundUser.password);
        if (foundUser) {
            if (foundUser.password === req.body.password) {
                res.render("secrets");
            }          
        } else {
            console.log(err);
        }
    });
});
app.listen(3000, function() {
    console.log("Server Started at port 3000");
}); 
 