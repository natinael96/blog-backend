import express from 'express'
const router = express.Router()

import  {
    signup,
	signin,
	signout,
	requireSignin,
	forgotPassword,
	resetPassword,
	preSignup,
	oauth } from '../controllers/auth.controller'

import {runValidation} from 'validators' // write the validators
import { 
        userSignUpValidator,
        userSignInValidator, 
        forgotPasswordValidator,
        resetPasswordValidator } from '../validators/authValidator' // 

router.post('/pre-signup', userSignUpValidator, runValidation, preSignup )
router.post('/signup', runValidation, signup)
router.post('/signin', userSignInValidator, runValidation, signin)
router.post('/signout', signout)

router.put('/forgot-pass',forgotPasswordValidator, runValidation, forgotPassword)
router.put('/reset-pass', resetPasswordValidator, runValidation, resetPassword)

router.post('/oauth', oauth)

module.exports = router
    