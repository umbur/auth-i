const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const KnexSessionStore = require('connect-session-knex')(session);
const dbConfig = require('../dbConfig.js');
const restricted = require('./restricted-middleware.js');


const Users = require('../helpers/model.js')
const server = express();
server.use(express.json());
server.use(cors());
server.use(helmet());

const sessionConfig = {
    name: 'monster',
    secret: 'the secret message',
    cookie: {
        maxAge: 1000 * 60 * 10,
        secure: false, // use cookie over https
        httpOnly: true, 
    },
    resave: false, // avoid recreating unchanged sessions
    saveUninitialized: false, // GDPR compliance
    store: new KnexSessionStore({
        knex: dbConfig,
        tablename: 'sessions',
        sidfieldname: 'sid',
        createtable: true,
        clearInterval: 1000 * 60 * 120, // delete expired sessions
    })
}
server.use(session(sessionConfig));


// *** End points ***
// POST Register end point
server.post('/api/register', (req, res) => {
    let user = req.body;
    if (user.username && user.password) {
        const hash = bcrypt.hashSync(user.password, 4);
        user.password = hash;
        Users.add(user)
        .then(saved => {
            res.status(201).json(saved);
        })
        .catch(err => {
            res.status(500).json({message: "The username exists!"});
        })
    } else {
        res.status(400).json({message: "Please make sure you have both username and password! "});
    }
})

// POST login endpoint
server.post('/api/login', (req, res) => {
    let {username, password } = req.body;

    Users.findBy({ username })
    .first()
    //console.log(username)
    .then(user => {
        //console.log(user)
        if(user && bcrypt.compareSync(password, user.password)){
           // req.session is added by express-session
           req.session.user = user;
           res.status(200).json({message: `Welcome ${user.username}!`}); 
        } else {
            res.status(401).json({message: 'Invalid Credentials!'})
        }
    }) .catch(error => {
        console.log(error);
        res.status(500).json({
            message: 'Internal error!'
           // error: error,
        });
    });
});


// GET users endpoint with the restricted middleware 
server.get('/api/users', restricted, (req, res) => {
    Users.find()
    .then(users => {
        res.json(users);
    })
    .catch(err => res.send(err));
})

// GET endpoint to logout
server.get('/api/logout', (req, res) => {
    if(req.session) {
        req.session.destroy(err => {
            if(err) {
                res.status(500).json({message: 'Error loging out!'})
            } else {
                res.status(200).json({message: 'You have successfuly loged out!'})
            }
        });
    } else {
        res.status(200).json({message: 'You have successfuly loged out!'})
    }
})
   
module.exports = server;
