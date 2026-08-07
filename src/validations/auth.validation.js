import {z} from 'zod';

//default validation schema for user sign up
export const signUpSchema = z.object({
  name: z.string().min(2).max(255).trim(),
  email: z.email().max(255).trim().toLowerCase(),
  password: z.string().min(6).max(128),
  role: z.enum(['user', 'admin']).default('user'),
});

//default validation schema for user sign in
export const signInSchema = z.object({
  email: z.email().toLowerCase().trim(),
  password: z.string().min(1),
});