import {z} from 'zod'

const schema = z.object({
  name: z.string().min(1, "Name is required"),
  email: z.string().email("Invalid email address"),
});

exports.runValidation = (req, res, next) => {
  const result = schema.safeParse(req.body);
  if (!result.success) {
    return res.status(422).json({ error: result.error.errors[0].message });
  }
  next();
};