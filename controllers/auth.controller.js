import User from '../models/user.model';
import Blog from '../models/blog.model';
import jwt from 'jsonwebtoken';
import expressJWT from 'express-jwt';
import { OAuth2Client } from 'google-auth-library'; 
import shortid from 'shortid';
import bcrypt from 'bcrypt';
import sgMail from '@sendgrid/mail';
import _ from 'lodash';
import { errorHandler } from '../middleware/errorHandler'; // Assuming you have a custom error handler module

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// pre-sign up  and send activation link
exports.preSignUp = (req, res) => {
    const { name, email, password } = req.body;
    
    User.findOne({ email }).exec((err, user) => {
        if (user) {
            return res.status(400).json({
                error: 'Email is already taken'
            });
        }

        const token = jwt.sign({ name, email, password }, process.env.JWT_ACTIVATION, { expiresIn: '15m' });

        const emailData = {
            from: process.env.EMAIL_FROM,
            to: email,
            subject: 'Account Activation Link',
            html: `
                <h1>Please use the following link to activate your account</h1>
                <p>${process.env.CLIENT_URL}/auth/activate/${token}</p>
                <hr />
                <p>This email may contain sensitive information</p>
                <p>${process.env.CLIENT_URL}</p>
            `
        };

        sgMail.send(emailData).then(() => {
            return res.json({
                message: `Email has been sent to ${email}. Follow the instructions to activate your account.`
            });
        }).catch(err => {
            return res.status(500).json({
                error: 'Email could not be sent. Try again later.'
            });
        });
    });
};

// Sign up - after activation link is clicked
exports.SignUp = (req, res) => {
    const { token } = req.body;
    if (token) {
        jwt.verify(token, process.env.JWT_ACTIVATION, (err, decoded) => {
            if (err) {
                return res.status(401).json({
                    error: 'Expired link. Sign up again.'
                });
            }

            const { name, email, password } = jwt.decode(token);
            const username = shortid.generate();
            const profile = `${process.env.CLIENT_URL}/profile/${username}`;

            bcrypt.hash(password, 12, (err, hashedPassword) => {
                if (err) {
                    return res.status(500).json({ error: 'Error hashing password' });
                }

                const user = new User({ name, email, password: hashedPassword, profile, username });
                user.save((err, user) => {
                    if (err) {
                        return res.status(401).json({
                            error: errorHandler(err)
                        });
                    }

                    return res.json({
                        message: 'Sign up success! Please sign in.'
                    });
                });
            });
        });
    } else {
        return res.json({
            message: 'Something went wrong. Try again.'
        });
    }
};

// log in
exports.SignIn = (req, res) => {
    const { email, password } = req.body;
    User.findOne({ email }).exec((err, user) => {
        if (err || !user) {
            return res.status(400).json({
                error: 'User with this email does not exist. Please sign up.'
            });
        }

        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (!isMatch || err) {
                return res.status(400).json({
                    error: 'Email and password do not match.'
                });
            }

            const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
            res.cookie('token', token, { expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) }); // Cookie for 7 days

            const { _id, username, name, email, role } = user;
            return res.json({
                token,
                user: { _id, username, name, email, role }
            });
        });
    });
};

// sign out
exports.SignOut = (req, res) => {
    res.clearCookie('token');
    return res.json({
        message: 'Sign out success'
    });
};

// middleware to require sign-in
exports.requireSignIn = expressJWT({
    secret: process.env.JWT_SECRET,
    algorithms: ['HS256'],
    userProperty: 'user'
});

// Authentication middleware for users
exports.authmiddleware = (req, res, next) => {
    const authUserId = req.user._id;
    User.findById(authUserId).exec((err, user) => {
        if (err || !user) {
            return res.status(400).json({ error: 'User not found' });
        }
        req.profile = user;
        next();
    });
};

// Admin middleware
exports.admin_middleware = (req, res, next) => {
    const adminUserId = req.user._id;
    User.findById(adminUserId).exec((err, user) => {
        if (err || !user || user.role !== 1) {
            return res.status(400).json({ error: 'Access denied' });
        }
        req.profile = user;
        next();
    });
};

// Forgot password
exports.forgotPassword = (req, res) => {
    const { email } = req.body;

    User.findOne({ email }).exec((err, user) => {
        if (err || !user) {
            return res.status(400).json({ error: 'User with that email does not exist.' });
        }

        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '10m' });

        const emailData = {
            from: process.env.EMAIL_FROM,
            to: email,
            subject: 'Password Reset Link',
            html: `
                <h1>Please use the following link to reset your password</h1>
                <p>${process.env.CLIENT_URL}/auth/password/reset/${token}</p>
                <hr />
                <p>This email may contain sensitive information</p>
                <p>${process.env.CLIENT_URL}</p>
            `
        };

        user.updateOne({ resetPasswordLink: token }).exec((err, success) => {
            if (err) {
                return res.status(400).json({ error: 'Password reset failed. Try again.' });
            }

            sgMail.send(emailData).then(() => {
                return res.json({
                    message: `Email has been sent to ${email}. Follow the instructions to reset your password.`
                });
            }).catch(err => {
                return res.status(500).json({
                    error: 'Email could not be sent. Try again later.'
                });
            });
        });
    });
};

// Reset password
exports.resetPassword = (req, res) => {
    const { resetPasswordLink, newPassword } = req.body;

    if (resetPasswordLink) {
        jwt.verify(resetPasswordLink, process.env.JWT_SECRET, (err, decoded) => {
            if (err) {
                return res.status(400).json({ error: 'Expired link. Try again.' });
            }
             
            // 
            User.findOne({ resetPasswordLink }).exec((err, user) => { 
                if (err || !user) {
                    return res.status(400).json({ error: 'Invalid link. Try again.' });
                }

                bcrypt.hash(newPassword, 12, (err, hashedPassword) => {
                    if (err) {
                        return res.status(500).json({ error: 'Error hashing password' });
                    }

                    const updateFields = {
                        password: hashedPassword,
                        resetPasswordLink: ''
                    };

                    user = _.extend(user, updateFields);

                    user.save((err, result) => {
                        if (err) {
                            return res.status(400).json({ error: errorHandler(err) });
                        }

                        res.json({
                            message: 'Password reset success. You can now log in with your new password.'
                        });
                    });
                });
            });
        });
    } else {
        return res.status(400).json({ error: 'Authentication error. Try again.' });
    }
};

// Check if user can update and delete blog post
exports.canUpdateAndDelete = (req, res, next) => {
    const slug = req.params.slug.toLowerCase();
    Blog.findOne({ slug }).exec((err, blog) => {
        if (err || !blog) {
            return res.status(400).json({
                error: errorHandler(err)
            });
        }
        let isAuthor = blog.postedBy._id.toString() === req.user._id.toString();
        if (!isAuthor) {
            return res.status(400).json({
                error: 'You are not authorized to perform this action'
            });
        }
        next();
    });
};


const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

exports.oauth = async (req, res) => {
    const { tokenId } = req.body;

    try {
        const response = await client.verifyIdToken({ idToken: tokenId, audience: process.env.GOOGLE_CLIENT_ID });
        const { email_verified, name, email, jti } = response.payload;

        if (email_verified) {
            // Check if the user already exists
            const user = await User.findOne({ email }).exec();

            if (user) {
                // User exists, generate a token
                const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET,);
                res.cookie('token', token, { expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) }); // Set cookie expiration
                const { _id, role, username } = user;

                return res.json({
                    token,
                    user: { _id, email, name, role, username },
                });
            } else {
                // Create a new user if it does not exist
                const username = shortid.generate();
                const profile = `${process.env.CLIENT_URL}/profile/${username}`;
                const password = jti; // jti as a placeholder for password

                const newUser = new User({ name, email, profile, username, password });
                const savedUser = await newUser.save();

                const token = jwt.sign({ _id: savedUser._id }, process.env.JWT_SECRET, { expiresIn: '30d' });
                res.cookie('token', token, { expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) }); // Set cookie expiration

                const { _id, role } = savedUser;
                return res.json({
                    token,
                    user: { _id, email, name, role, username },
                });
            }
        } else {
            return res.status(400).json({ error: 'Google login failed, try again' });
        }
    } catch (error) {
        return res.status(400).json({ error: errorHandler(error) });
    }
};
