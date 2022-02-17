require('dotenv').config();
require('./config/database').connect();

const express = require('express');
const User = require('./models/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const auth = require('./middleware/auth');

const app = express();

app.use(express.json());
app.use(cookieParser());

app.get('/', (req, res) => {
        return res.send("<h1>Hello from auth system</h1>");
});

app.post('/register', async (req, res) => {
        try {
                const {firstname, lastname, email, password} = req.body;
                console.log(lastname);
                if(!(firstname && lastname && email && password)){
                        return res.status(400).send("All fields are required!");
                }
                const existingUser = await User.findOne({ email }); // returns a promise

                if(existingUser){
                        return res.status(401).send("User already registered!");
                }

                const encryptdPassword = await bcrypt.hash(password, 10);

                const user = await User.create({
                        firstname,
                        lastname,
                        email: email.toLowerCase(), 
                        password: encryptdPassword
                });
                const token = jwt.sign(
                        {userId: user._id, email},
                        process.env.SECRET_KEY,
                        {
                                expiresIn: "8h"
                        }
                )

                user.token = token;

                /*
                *to avoid sending password to front end with other fields of user model we have to asign it as undefined
                *however it will not set undefined in database
                 */
                user.password = undefined;
                return res.status(201).json(user);
        } catch (error) {
                console.log(error);
        }                        
});

app.post('/login', async (req, res) => {
        try {
                const {email, password} = req.body;

                if(!(email && password)) res.status(400).send("email or password missing!");
                const user = await User.findOne({email});
                if(!user){
                        return res.status(400).send("You are not register, please register first then try to login again!");
                }
                console.log(user);
                if(!(await bcrypt.compare(password, user.password))){
                        return res.status(400).send("Incorrect password!");
                }
                const token = await jwt.sign(
                        {user_id: user._id, email},
                        process.env.SECRET_KEY,
                        {
                                expiresIn: "8h"
                        }
                );
                user.token = token;
                user.password = undefined;
                //return res.status(200).json(user);
                //setting up cookie
                const options = {
                        expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),  //setting expiry for cokkie 3 days
                        httpOnly: true
                };
                res.status(200).cookie('token', token, options).json({
                        success: true,
                        user,
                        token
                });
        } catch (error) {
                console.log('Error while login!');
        }
});

app.get('/dashboard', auth, (req, res) => {
        return res.status(201).send("dashboard");
})
module.exports = app;