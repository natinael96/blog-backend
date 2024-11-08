import Blog from '../models/blog.model'
import User from '../models/user.model'
import Tag from '../models/tags.model'
import Category from '../models/category.model'

import slugify from 'slugify'
import stripHtml from 'string-strip-html'
import _ from 'lodash'
import fs from 'fs'
import { errorHandler } from '../middleware/errorHandler'
import {smartTrim} from '../middleware/blog' // implement the trim
import formidable from 'formidable'

exports.create = (req, res) => {
    // make it as latest as possible

    let form  = new formidable.IncomingForm() // form data
    form.keepExtensions = true

    form.parse(req, (err, fields, files) => {
        if (err) {
            return res.status(400).json({
                err: 'Image could not upload'
            })
        }

        const {title, body, Category, tags} = fields

        if (!title.length || !title){
            return res.status(400).json({
                err: 'Title is required'
            })
        }

        if (!body || !body.length){
            return res.status(400).json({
                err: 'Content is required'
            })
        }

        if (!Category || !Category.length){
            return res.status(400).json({
                err: 'Category is required'
            })
        }

        if (!tags || !tags.length){
            return res.status(400).json({
                err: 'Tags is required'
            })
        }

        let blog = new Blog()
        blog.title = title
        blog.body = body
        blog.slug = slugify(title).toLowerCase() // slugify the title
        blog.excerpt = smartTrim(body, 320, ' ', '...') // trim the body

        body.mtitle = stripHtml(body.substring(0, 160)) // strip the html tags
        body.mdesc = stripHtml(body.substring(0, 160)) // strip the html tags
        body.postedBy = req.user._id
        body.category = Category && Category.split(',')
        body.tags = tags && tags.split(',')

        if (files.photo){
            if (files.photo.size > 10000000){
                return res.status(400).json({
                    err: 'Image size is too large'
                })
            }
            
            blog.photo.data = fs.readFileSync(files.photo.path)
            blog.photo.contentType = files.photo.type
            blog.save()
            .then(result => {
                res.json(result)
            })
            .catch(err => {(
                res.status(400).json({
                    error : errorHandler(err)
                })
            )})

            
        }


    })

}