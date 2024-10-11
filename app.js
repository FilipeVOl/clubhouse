const express = require("express");
const session = require("express-session");
const passport = require("passport");
const path = require("path");
const router = require("./routes/router");

const app = express();
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: "dogs", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

app.use((req, res, next) => {
    res.locals.user = req.user;
    res.locals.messages = req.messages;
    next();
  });
  
  app.use("/", router);


app.listen(3000, () => {
    console.log("Server is running on port 3000");
    });

