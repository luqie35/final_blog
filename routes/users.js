// Register User
const express = require("express");
const router = express.Router();

// Bcrypt
const bcrypt = require("bcryptjs");

// Json webtoken
const jwt = require("jsonwebtoken");
const config = require("config");

// Express Validator
const { check, validationResult } = require("express-validator");

// Bringing the user schema into users
const User = require("../models/User");

// @route   POST api/users
// @desc    Register a user
// @access  Public
router.post(
  "/",
  [
    // Setting all the check to be made
    check("name", "Please add name").not().isEmpty(),
    check("email", "Please include a valid email").isEmail(),
    check(
      "password",
      "Please enter a password with 6 or more characters"
    ).isLength({
      min: 6,
    }),
  ],
  async (req, res) => {
    // Error Variable
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // Using the destructing method to pull out the name, email, password
    const { name, email, password } = req.body;

    try {
      let user = await User.findOne({ email });

      // Checking if user exist based on email
      if (user) {
        return res.status(400).json({ msg: "User already exists" });
      }

      // Set a new user
      user = new User({
        name,
        email,
        password,
      });

      // Encrypting the password
      const salt = await bcrypt.genSalt(10);

      user.password = await bcrypt.hash(password, salt);

      await user.save();

      // Creating the payload variable
      const payload = {
        user: {
          id: user.id,
        },
      };

      jwt.sign(
        payload,
        config.get("jwtSecret"),
        {
          expiresIn: 360000,
        },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send("Server Error");
    }
  }
);

module.exports = router;
