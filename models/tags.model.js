import mongoose from "mongoose";

const tagSchema = new mongoose.Schema({
    name:{
        type: String,
        trim: true,
        required: true,

    },
    slug: {
        type: String,
        unique: true,
        index: true,
    }
})

module.exports = mongoose.model('Tag', tagSchema)
