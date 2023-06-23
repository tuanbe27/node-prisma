import { RoleEnumType } from '@prisma/client';
import { object, string, TypeOf, z } from 'zod';

export const registerUserSchema = object({
  body: object({
    name: string({
      required_error: 'Name is required',
    }),
    email: string({
      required_error: 'Email address is required',
    }).email('Invalid email address'),
    password: string({
      required_error: 'Password is required',
    }).regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,32}$/,
      'assword must be minimum eight characters, at least one uppercase letter, one lowercase letter, one number and one special character'
    ),
    passwordConfirm: string({
      required_error: 'Please confirm your password',
    }),
    role: z.optional(z.nativeEnum(RoleEnumType)),
  }).refine((data) => data.password === data.passwordConfirm, {
    path: ['passwordConfirm'],
    message: 'Passwords do not match',
  }),
});

export const loginUserSchema = object({
  body: object({
    email: string({ required_error: 'Email address is required' }).email(
      'Invalid email address'
    ),
    password: string({ required_error: 'Password is required' }).regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,32}$/,
      'Invalid email or password'
    ),
  }),
});

export const forgotPasswordSchema = object({
  body: object({
    email: string({
      required_error: 'Email is required',
    }).email('Email is invalid'),
  }),
});

export const resetPasswordSchema = object({
  params: object({
    resetToken: string(),
  }),
  body: object({
    password: string({ required_error: 'Password is required' }).regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,32}$/,
      'Minimum eight characters, at least one uppercase letter, one lowercase letter, one number and one special character'
    ),
    confirmPassword: string({ required_error: 'Password is required' }).regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,32}$/,
      'Minimum eight characters, at least one uppercase letter, one lowercase letter, one number and one special character'
    ),
  }).refine((data) => data.password === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['passwordConfirm'],
  }),
});

export type RegisterUserInput = Omit<
  TypeOf<typeof registerUserSchema>['body'],
  'passwordConfirm'
>;

export type LoginUserInput = Omit<TypeOf<typeof loginUserSchema>['body'], ''>;

export const verifyEmailSchema = object({
  params: object({
    verificationCode: string(),
  }),
});

export type VerifyEmailInput = TypeOf<typeof verifyEmailSchema>['params'];

export type ForgotPasswordInput = TypeOf<typeof forgotPasswordSchema>['body'];
export type ResetPasswordInput = TypeOf<typeof resetPasswordSchema>;
