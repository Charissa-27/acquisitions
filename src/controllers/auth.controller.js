import { signUpSchema, signInSchema } from '#validations/auth.validation.js';
import { formatValidationError } from '#utils/format.js';
import { createUser, authenticateUser } from '#services/auth.service.js'; 
import { jwttoken } from '#utils/jwt.js';
import { cookies } from '#utils/cookies.js';
import logger from '#config/logger.js';


export const signUp = async (req, res, next) => {
  try{
    const validationResult = signUpSchema.safeParse(req.body);
    if (!validationResult.success) {
      return res.status(400).json({
        error: 'Validation failed',
        details: formatValidationError(validationResult.error)
      });
    };
    // If validation is successful, proceed with the sign-up logic
    const { name, email, password, role } = validationResult.data;

    // AUTH SERVICE
    const user = await createUser({ name, email, password, role });
    const token = jwttoken.sign({ id: user.id, email: user.email, role: user.role });
    cookies.set(res, 'token', token);

    logger.info(`User registered successfully with email: ${email}`);
    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      }
    });

  } catch (err) {
    logger.error('Error during sign-up', err);

    /*
    if (err.message === 'User with this email already exists') {
      return res.status(409).json({ error: 'User with this email already exists' });
    }
  */
    if (err.message.includes('duplicate')) {
      return res.status(409).json({ error: 'User with this email already exists' });
    }
    //next(err);
    return res.status(500).json({
      error: err.message || 'Internal Server Error',
      message: 'An error occurred during sign-up. Please try again later.'
    });
  }
};

export const signIn = async (req, res, next) => {
  try {
    const validationResult = signInSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(400).json({
        error: 'Validation failed',
        details: formatValidationError(validationResult.error)
      });
    };

    const { email, password } = validationResult.data;
    
    // AUTH SERVICE
    const user = await authenticateUser({ email, password });
    const token = jwttoken.sign({ 
      id: user.id, 
      email: user.email, 
      role: user.role 
    });
    cookies.set(res, 'token', token);

    logger.info(`User signed in successfully with email: ${email}`);
    res.status(200).json({
      message: 'User signed in successfully',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      }
    });

  } catch (err) {
    logger.error('Error during sign-in', err);

    if (err.message === 'User not found' || err.message === 'Invalid password') {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    //next(err); 
    return res.status(500).json({
      error: err.message || 'Internal Server Error',
      message: 'An error occurred during sign-in. Please try again later.'
    
    }); 
  };
};

export const signOut = async (req, res, next) => {
  try {
    cookies.clear(res, 'token');

    logger.info('User signed out successfully');
    res.status(200).json({
      message: 'User signed out successfully'
    });
  } catch (err) {
    logger.error('Error during sign-out', err);
    //next(err);
    return res.status(500).json({
      error: err.message || 'Internal Server Error',
      message: 'An error occurred during sign-out. Please try again later.'
    });
  }
};