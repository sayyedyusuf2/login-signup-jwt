const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const tokenSecret = 'some-secret';
const bcrypt = require('bcrypt');

mongoose.connect('mongodb://localhost:27017/basic-auth')
.then(() => console.log('DB connection is successful'))
.catch((e) => console.log(e));

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    role: String
});

const User = mongoose.model('User', userSchema);

function authorizeRoles (...roles) {
    return (req, res, next) => {
        if (roles.includes(req.user.role)){
            next();
        } else {
            return res.status(403).json({
                status: 'bad request',
                message: 'you are not authorized to access this resource',
                data: {}
            });
        }
    };
};

function createToken (id) {
    return jwt.sign({id}, tokenSecret);
};

async function verifyToken (req, res, next) {
    if (!req.headers.authorization) {
        return res.status(400).json({
            status: 'bad request',
            message: 'authorization token is required',
            data: {}
        });
    }
    const token = req.headers.authorization.split(' ')[1];
    const decoded = jwt.verify(token, tokenSecret)
    if (decoded) {
        let user; 
        try {
            user = await User.findOne({_id: mongoose.Types.ObjectId(decoded.id)});
        } catch (e) {
            return res.status(500).json({
                status: 'error occured',
                message: 'internal server error',
                data: {}
            });
        }

        if (!user) {
            return res.status(404).json({
                status: 'bad request',
                message: 'no such user',
                data: {}
            });
        }

        req.user = user;
        next();
    } else {
        return res.status(400).json({
            status: 'bad request',
            message: 'invalid token',
            data: {}
        });
    }
};

const app = express();

app.use(express.json());


app.post('/signup', async (req, res) => {
    let user;

    if (!req.body.email) {
        return res.status(400).json({
            status: 'bad request',
            message: 'email id is required',
            data: {}
        });
    }

    if (!req.body.password) {
        return res.status(400).json({
            status: 'bad request',
            message: 'password is required',
            data: {}
        });
    }

    if (!req.body.role) {
        return res.status(400).json({
            status: 'bad request',
            message: 'role is required',
            data: {}
        });
    }
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    try {
        user = await User.create({
            email: req.body.email,
            password: hashedPassword,
            role: req.body.role
        });
    } catch (e) {
        return res.status(500).json({
            status: 'error occured',
            message: 'internal server error',
            data: {}
        });
    }

    const token = createToken(user._id);

    return res.status(201).json({
        status: 'successful',
        message: 'user signedup successfully',
        data: {
            user: user,
            token: token
        }
    })
});

app.post('/login', async (req, res) => {
    let user;

    if (!req.body.email) {
        return res.status(400).json({
            status: 'bad request',
            message: 'email id is required',
            data: {}
        });
    }

    if (!req.body.password) {
        return res.status(400).json({
            status: 'bad request',
            message: 'password is required',
            data: {}
        });
    }

    try {
        user = await User.findOne({
            email: req.body.email
        });
    } catch (e) {
        return res.status(500).json({
            status: 'error occured',
            message: 'internal server error',
            data: {}
        });
    }

    if (user) {
        bcrypt.compare(req.body.password, user.password, function (err, result) {
            if (result) {
                const token = createToken(user._id);
                return res.status(200).json({
                    status: 'successful',
                    message: 'user loggedin successfully',
                    data: {
                        user: user,
                        token: token
                    }
                });
            } else {
                return res.status(400).json({
                    status: 'bad request',
                    message: 'invalid email or password',
                    data: {}
                });
            }
        });
    } else {
        return res.status(404).json({
            status: 'bad request',
            message: 'no such user',
            data: {}
        });
    }
});

app.get('/users', verifyToken, authorizeRoles('Admin'), async (req, res) => {
    let users;

    try {
        users = await User.find({});
    } catch (e) {
        return res.status(500).json({
            status: 'error occured',
            message: 'internal server error',
            data: {}
        });
    }

    return res.status(200).json({
        status: 'successful',
        message: 'users fetched successfully',
        data: {
            users: users
        }
    })
});

app.listen(3000, () => console.log('server is running on port 3000'));