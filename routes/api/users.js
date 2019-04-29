const express = require("express");
const router = express.Router();
const gravatar = require("gravatar");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const keys = require("../../config/keys");
const passport = require("passport");

// Load Input validation
const validateRegisterInput = require("../../validation/register");
const validateLoginInput = require("../../validation/login");

// Load User model
const User = require("../../models/User");

// @route GET api/users/test
// @desc Test post users
// @access public
router.get("/test", (req, res) =>
  res.json({
    msg: "Users Works"
  })
);

// @route POST api/users/register
// @desc Register user
// @access public
router.post("/register", (req, res) => {
  const { errors, isValid } = validateRegisterInput(req.body);

  // Check validation
  if (!isValid) {
    return res.status(400).json(errors);
  }

  User.findOne({
    email: req.body.email
  }).then(user => {
    if (user) {
      errors.email = "Email already exists";
      return res.status(400).json(errors);
    } else {
      const avatar = gravatar.url(req.body.email, {
        s: "200", // Size
        r: "pg", //Rating
        d: "mm" // Default
      });

      const newUser = new User({
        name: req.body.name,
        email: req.body.email,
        avatar,
        password: req.body.password
      });

      bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(newUser.password, salt, (err, hash) => {
          if (err) throw err;
          newUser.password = hash;
          newUser
            .save()
            .then(user => res.json(user))
            .catch(console.log(err));
        });
      });
    }
  });
});

// @route POST api/users/login
// @desc Login user / Returning JWT Token
// @access public
router.post("/login", (req, res) => {
  const { errors, isValid } = validateLoginInput(req.body);

  // Check validation
  if (!isValid) {
    return res.status(400).json(errors);
  }

  const email = req.body.email;
  const password = req.body.password;

  // Find user by email
  User.findOne({
    email
  }).then(user => {
    // Check for user. User is the user if it's found and false if not
    if (!user) {
      errors.email = "User not found";
      return res.status(404).json(errors);
    }

    // Check Password
    bcrypt
      .compare(password, user.password) // generates a promise with a bool if the passwords match
      .then(isMatch => {
        if (isMatch) {
          // User Matched

          const payload = {
            id: user.id,
            name: user.name,
            avatar: user.avatar
          }; // Create JWT Payload

          // Sign Token
          jwt.sign(
            payload,
            keys.secretOrKey,
            {
              expiresIn: 3600 // expires in one hour
            },
            (err, token) => {
              res.json({
                success: true,
                token: "Bearer " + token
              });
            }
          ); // Must relogin after an hour
        } else {
          errors.password = "Password incorrect";
          return res.status(400).json(errors);
        }
      });
  });
});

// @route GET api/users/current
// @desc Return current user
// @access private
router.get(
  "/current",
  passport.authenticate("jwt", { session: false }), // authenticates and returns a protected route
  (req, res) => {
    res.json({
      id: req.user.id,
      name: req.user.name,
      email: req.user.email
    });
  }
);

module.exports = router;
