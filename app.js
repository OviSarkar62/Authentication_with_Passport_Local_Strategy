require("dotenv").config();
require("./Config/database");
require("./Config/passport");
const express = require("express");
const cors = require("cors");
const ejs = require("ejs");
const USER = require("./Models/userModel");
const bcrypt = require("bcrypt");
const saltRounds = 10;

const passport = require("passport");
const session = require("express-session");
const MongoStore = require('connect-mongo');
const app = express();


app.set("view engine", "ejs");
app.use(cors());
app.use(express.urlencoded({extended: true}));
app.use(express.json());
app.use(express.static("public"));

app.set("trust proxy", 1)
app.use(session({
  secret: "keyboard cat",
  resave: false,
  saveUninitialized: true,
  store: MongoStore.create({
    mongoUrl: process.env.DB_URL,
    collectionName: "sessions"
  })
  // cookie: { secure: true }
})
);

app.use(passport.initialize());
app.use(passport.session());

// home
app.get("/",(req,res)=>{
    res.render("index");
})

// register
app.get("/register",(req,res)=>{
    res.render("register");
})

app.post("/register",async (req,res)=>{
    try{
        const user = await USER.findOne({username: req.body.username});
        if(user){
            res.status(400).send("User already exists");
        } else{
            bcrypt.hash(req.body.password, saltRounds, async(err, hash)=>{
                const newUser = new USER({
                    username: req.body.username,
                    password:hash,
                });
            await newUser.save();
            res.redirect("/login");
            });
        }
        } catch(error){
        res.status(500).send(error.message);
    }
});
// check loggedIn
const checkLoggedIn = (req, res, next) => {
    if (req.isAuthenticated()) {
      return res.redirect("/profile");
    }
    next();
  };

// login : get
app.get("/login", checkLoggedIn, (req, res) => {
    res.render("login");
  });

// login : post
app.post(
    "/login",
    passport.authenticate("local", {
      failureRedirect: "/login",
      successRedirect: "/profile",
    })
  );

  const checkAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
      return next();
    }
    res.redirect("/login");
  };

// profile protected route
app.get("/profile", checkAuthenticated, (req, res) => {
    res.render("profile");
  });

// logout route
app.get("/logout", (req, res) => {
    try {
      req.logout((err) => {
        if (err) {
          return next(err);
        }
        res.redirect("/");
      });
    } catch (error) {
      res.status(500).send(error.message);
    }
  });


module.exports = app;