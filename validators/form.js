import {z} from 'zod'

exports.contactFormValidator = z.object({
    name: z.string().min(1, 'Name is Required'),
    email: z.string().min(1, 'email is Required'),
    message: z.string(1, 'Message is Required').min(10, 'Message must at least be 10 characters long')
})
