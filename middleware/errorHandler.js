export const errorHandler = (err, req, res, next) => {
    // Set default status code to 500 for server errors
    const statusCode = err.statusCode || 500;

    // Custom error handling
    if (err.name === 'ValidationError') {
        // Handle Mongoose validation errors
        return res.status(400).json({
            error: 'Validation Error',
            message: Object.values(err.errors).map(val => val.message).join(', ')
        });
    }

    if (err.name === 'JsonWebTokenError') {
        // Handle JWT authentication errors
        return res.status(401).json({
            error: 'Unauthorized',
            message: 'Invalid or expired token. Please sign in again.'
        });
    }

    if (err.name === 'TokenExpiredError') {
        // Handle expired JWT tokens
        return res.status(401).json({
            error: 'Unauthorized',
            message: 'Your session has expired. Please sign in again.'
        });
    }

    if (err.code && err.code === 11000) {
        // Handle MongoDB duplicate key error (e.g., email or username already exists)
        const field = Object.keys(err.keyValue)[0];
        return res.status(400).json({
            error: 'Duplicate Field Error',
            message: `The ${field} is already taken. Please choose another one.`
        });
    }

    if (err.name === 'CastError') {
        // Handle invalid ObjectId (e.g., when searching for a blog post by ID)
        return res.status(400).json({
            error: 'Invalid ID',
            message: `The ID ${err.value} is not valid for ${err.path}.`
        });
    }

    // Handle permission errors (e.g., editing or deleting someone else’s blog)
    if (err.message === 'UnauthorizedAction') {
        return res.status(403).json({
            error: 'Forbidden',
            message: 'You do not have permission to perform this action.'
        });
    }

    // Fallback for generic or unknown errors
    return res.status(statusCode).json({
        error: err.message || 'An unknown error occurred',
    });
};
