var mongoose = require('mongoose');
var passport = require('passport');
var config = require('../config/database');
require('../config/passport')(passport);
var express = require('express');
var jwt = require('jsonwebtoken');
var router = express.Router();
var User = require("../models/user");
// nodemailer
var nodemailer = require('nodemailer');

var smtpTransport = nodemailer.createTransport({
  host: "smtp-mail.outlook.com", // hostname
    secureConnection: false, // TLS requires secureConnection to be false
    port: 587, // port for secure SMTP
    tls: {
       ciphers:'SSLv3'
    },
    auth: {
        user: 'email@outlook.com',
        pass: 'password'
    }
});

var rand, mailOptions, host, link, userId;

router.post('/signup', function(req, res) {
  if (!req.body.username || !req.body.password || !req.body.email) {
    res.json({success: false, msg: 'Please pass email, username and password.'});
  } else {
    var newUser = new User({
      email: req.body.email,
      username: req.body.username,
      password: req.body.password,
      active: false,
      donar: false
    });
    // save the user
    newUser.save(function(err, response) {
      if (err) {
        return res.status(404).json({success: false, msg: 'Username or email already exists.', error: err});
      }
      this.userId = response._id;
      // send confirmation email
      rand = Math.floor((Math.random() * 1000000000) + 69);
      host = req.get('host');
      link = "http://" + host + "/api/verify?id=" + rand;
      mailOptions = {
        to: req.body.email,
        subject : "Please confirm your Email account",
        html : "Hello,<br> Please Click on the link to verify your email.<br><a href="+link+">Click here to verify</a>"
      },
      console.log(mailOptions);
      smtpTransport.sendMail(mailOptions, function(err, resp){
        if(err){
          res.status(404).json({success: false, msg: 'send mail failed', error:err});
        } else {
          res.json({success: true, msg: 'Successful created new user. please verify your email.', response: response});
        }
      });
      
    });
  }
});

router.get('/verify', function(req, res){
  console.log(req.protocol+":/"+req.get('host'));
  if((req.protocol+"://"+req.get('host'))==("http://"+host))
  {
      console.log("Domain is matched. Information is from Authentic email");
      if(req.query.id==rand)
      {
        this.rand = null;
        User.update({_id: this.userId}, { active: true }, function(err, resp){
          if(err){
            res.status(404).json({ success: false, msg: 'can not update user.', err: err});
          } else {
            console.log("email is verified");
            res.redirect("http://"+host+"/login");
          }
        });
        
      }
      else
      {
          console.log("email is not verified");
          res.json("<h1>Bad Request</h1>");
      }
  }
  else
  {
      res.json("<h1>Request is from unknown source</h1>");
  }
})

router.post('/signin', function(req, res) {
  User.findOne({
    username: req.body.username
  }, function(err, user) {
    if (err) throw err;

    if (!user) {
      res.status(401).send({success: false, msg: 'Authentication failed. User not found.'});
    }
    // check if user is active
    else if(user.active == false){
      res.status(401).send({ success: false, msg: 'User is not active, please verify email.'});
    }
    else {
      // check if password matches
      user.comparePassword(req.body.password, function (err, isMatch) {
        if (isMatch && !err) {
          // if user is found and password is right create a token
          var token = jwt.sign(user.toJSON(), config.secret);
          // return the information including token as JSON
          res.json({success: true, token: 'JWT ' + token});
        } else {
          res.status(401).send({success: false, msg: 'Authentication failed. Wrong password.'});
        }
      });
    }
  });
});

router.post('/book', passport.authenticate('jwt', { session: false}), function(req, res) {
  var token = getToken(req.headers);
  if (token) {
    console.log(req.body);
    var newBook = new Book({
      isbn: req.body.isbn,
      title: req.body.title,
      author: req.body.author,
      publisher: req.body.publisher,
      published_year: req.body.published_year
    });

    newBook.save(function(err, book) {
      if (err) {
        return res.json({success: false, msg: 'Save book failed.' + err});
      }
      res.json({success: true, _id: book._id, msg: 'Successful created new book.'});
    });
  } else {
    return res.status(403).send({success: false, msg: 'Unauthorized.'});
  }
});

getToken = function (headers) {
  if (headers && headers.authorization) {
    var parted = headers.authorization.split(' ');
    if (parted.length === 2) {
      return parted[1];
    } else {
      return null;
    }
  } else {
    return null;
  }
};

module.exports = router;
