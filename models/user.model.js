import mongoose from 'mongoose';
import bcrypt from 'bcryptjs'; 

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        trim: true,
        required: true,
    },
    userName: {
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
        lowercase: true,
    },
    password: {
        type: String,
        required: true,
    },
    about: {
        type: String, 
        trim: true,
    },
    role: {
        type: Number,
        default: 0, 
    },
    photo: {
        data: Buffer,
        contentType: String,
    },
    followers: [{ type: mongoose.Schema.ObjectId, ref: 'User' }], 
    following: [{ type: mongoose.Schema.ObjectId, ref: 'User' }],
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
    github: {
        type: String,
        trim: true,
    },
    instagram: {
        type: String,
        trim: true,
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
    timestamps: true 
});

userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next(); 
    try {
        const salt = await bcrypt.genSalt(10); 
        this.password = await bcrypt.hash(this.password, salt); 
        next();
    } catch (err) {
        next(err);
    }
});

userSchema.methods = {
    authenticate: async function(plainText) {
        return bcrypt.compare(plainText, this.password); 
    }
};

export default mongoose.model('User', userSchema);
