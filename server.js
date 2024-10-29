import express from 'express'
import mongoose from 'mongoose'
import morgan from 'morgan'
import bodyParser from 'body-parser'
import cookieParser from 'cookie-parser'
import cors from 'cors'
import dotenv from 'dotenv'

import expressValidator from 'express-validator'


const app = express()

const port = process.env.PORT || 8000
app.listen(port, () => {
    console.log(`App is listening on port: ${port}`)
})

