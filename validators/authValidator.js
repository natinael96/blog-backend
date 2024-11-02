import {z} from 'zod'

exports.userSignupValidator = z.object({
  name: z.string().min(1, "Name is required"),
  email: z.string().email("Must be a valid email address"),
  password: z.string().min(7, "Password must be at least 7 characters long"),
});

exports.userSignInValidator = z.object({
  email: z.string().email("Must be a valid email address"),
  password: z.string().min(7, "Password must be at least 7 characters long"),
});

exports.forgotPasswordValidator = z.object({
  email: z.string().min(1, "Must be a valid email address").email("Must be a valid email address"),
});

exports.resetPasswordValidator = z.object({
  newPassword: z.string().min(1, "Password is required").min(7, "Password must be at least 7 characters long"),
});
