import User from '../models/user.model';
import Blog from '../models/blog.model';
import jwt from 'jsonwebtoken'
import expressJWT from 'express-jwt'
import OAuth2Client from 'google-auth-library'   

const apiKey = process.env.SENDGRID_API_KEY;

exports.preSignUp