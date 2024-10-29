import mongoose from "mongoose";

const blogSchema = new mongoose.Schema({
    title : {
        type: String,
        require: true,
        trim: true,
        min: 3,
    },
    body: {
        type: {},
        require: true,
        trim: true,
        max: 2000000,
    },
    slug: {
        type: String,
        unique: true,
        index: true,
    },
    mtitle: {
        type: String,
    },
    mdesc: {
        type: {},
    },
    photo : {
        data: Buffer,
        contentType: String,
    },
    catagories: [{type: mongoose.Schema.ObjectId, ref: 'Category', required: true}],

    tags: [{type: mongoose.Schema.ObjectId, ref: 'Tag', required: true}],

    postedBy: {type: mongoose.Schema.ObjectId,ref: 'User', required: true},
    }, 
    {
        timeStamps : true,
    }
)

module.exports =  mongoose.model('Blog', blogSchema)