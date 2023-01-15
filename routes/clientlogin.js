const express = require("express");
const pool = require("./pool");
var router = express.Router();

const bcrypt = require("bcrypt");

const saltRound = 10;
const jwt = require("jsonwebtoken");
const { response, json } = require("express");

router.post("/register", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  bcrypt.hash(password, saltRound, (err, hash) => {
    if (err) {
      console.log(err);
    }
    pool.query(
      "INSERT INTO users (username,password) VALUES (?,?)",
      [username, hash],
      (err, result) => {
        if (err) {
          res
            .status(200)
            .json({ status: false, result: "Registration Failed" });
        } else
          res
            .status(200)
            .json({ status: true, result: "Successfully Registerd" });
      }
    );
  });
});

const verifyJWT = (req, res, next) => {
  console.log(req.headers);
  const token = req.headers.authorization;
  console.log("Token:", token);
  if (!token) {
    res.send("We need a token, please give it to us next time");
  } else {
    jwt.verify(token, "jwtSecret", (err, decoded) => {
      console.log(decoded);
      if (err) {
        console.log(err);
        res.json({ auth: false, message: "you are failed to authenticate" });
      } else {
        req.userID = decoded.id;
        next();
      }
    });
  }
};

router.get("/isUserAuth", verifyJWT, (req, res) => {
  res.send("You are authenticated Congrats");
});

router.get("/login", (req, res) => {
  if (req.session.user) {
    res.send({ loggedIN: true, user: req.session.user });
  } else {
    res.send({ loggedIN: false });
  }
});

router.post("/login", (req, res) => {
  console.log(req.body);
  const username = req.body.username;
  const password = req.body.password;
  pool.query(
    "SELECT * FROM users WHERE username =?;",
    [username],
    (err, result) => {
      if (err) {
        res.send({ err: err });
      }
      if (result.length > 0) {
        bcrypt.compare(password, result[0].password, (error, response) => {
          if (response) {
            const id = result[0].id;
            console.log(id);
            const token = jwt.sign({ id }, "jwtSecret", {
              expiresIn: "1h",
            });
            console.log("XXXXXXXXXX");
            res.json({ auth: true, token: token, result: result });
          } else {
            console.log("errrrrrr");
          }
        });
      } else {
        json({ auth: false, message: "No user Exists" });
      }
    }
  );
});
module.exports = router;
