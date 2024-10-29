import mongoose from 'mongoose'
import { reset } from 'nodemon'

const userSchema = new mongoose.Schema({
    name: {
        type : String,
        trim: true,
        required: true,
    },
    userName : {
        type: String,
        trim: true,
        required: true,
        unique: true,
        lowercase: true,
    },
    email: {
        type: String,
        trim: true,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    about: {
        type: {},
        trim: true,
    },
    role: {
        type: Number,
        trim: true,
    },
    photo: {
        data: Buffer,
        contentType: String,
    },
    follower : [{type: mongoose.Schema.ObjectId, ref: 'User'}],
    following : [{type: mongoose.Schema.ObjectId, ref: 'User'}],
    about: {
        type: {},
        trim: true,
    },
    website: {
        type: String,
        trim: true,
    },
    linkedin: {
        type: String,
        trim: true,
    },
    x: {
        type: String,
        trim: true,
    },
    github : {
        type: String,
        trim: true,
    },
    instagram: {
        type: String,
        trim : true,
    },
    facebook: {
        type: String,
        trim: true,
    },
    resetPasswordLink: {
        data: String,
        default: '',
    },
}, {
    timeStamps: true
})

userSchema
    .virtual('password')
    .set(function(password){
        this.tmpPassword = password
        this.salt = this.makeSalt()
        this.hashedPassword = this.encryptPassword(password)
    })

    .get(function(){
        return this.tmpPassword
    })
userSchema.methods = {
    authenticate : function(plainText){
        return this.encryptPassword(plainText) === this.hashedPassword;
    },

    encryptPassword: function(password){
        if(!password) return ''
        try {
            return crypto.create(sha256, this.salt).update(password).digest('hex')  
        } catch (error) {
            return `${error}`
        }
    },

    makeSalt: function(){
        return Math.round(new Date().valueOf() * Math.random()) + ''
    }
}

module.exports = mongoose.model('User', userSchema)