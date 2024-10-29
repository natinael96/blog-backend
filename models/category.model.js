import mongoose from "mongoose";

const categorySchema = new mongoose.Schema({
    name : {
        type: String,
        trim: true,
        required : true,
    },
    slug:{
        type: String,
        unique: true,
        index: true,
    }
})

module.exports = mongoose.model('Category', categorySchema)
