import crypto from 'crypto';

import { Prisma } from '@prisma/client';
import { NextFunction, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import config from 'config';

import {
  LoginUserInput,
  RegisterUserInput,
  VerifyEmailInput,
} from '../schemas/user.schema';
import {
  createUser,
  findUniqueUser,
  signTokens,
  updateUser,
} from '../services/user.service';
import {
  accessTokenCookieOption,
  refreshTokenCookieOptions,
} from '../services/token.service';
import AppError from '../utils/handleResponse';
import { signJwt, verifyJwt } from '../utils/jwt';
import { TokenType } from '../types';
import redisClient from '../utils/connectRedis';
import Email from '../utils/email';

// Register User Controller
export const registerUserHandler = async (
  req: Request<object, object, RegisterUserInput>,
  res: Response,
  next: NextFunction
) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 12);

    const verifyCode = crypto.randomBytes(32).toString('hex');

    const verificationCode = crypto
      .createHash('sha256')
      .update(verifyCode)
      .digest('hex');

    const user = await createUser({
      name: req.body.name,
      email: req.body.email.toLowerCase(),
      password: hashedPassword,
      verificationCode,
    });

    const rediectUrl = `${config.get<string>(
      'origin'
    )}/api/auth/verifyemail/${verifyCode}`;

    try {
      await new Email(user, rediectUrl).sendVerificationCode();
      await updateUser({ id: user.id }, { verificationCode });

      res.status(201).json({
        status: 'success',
        message:
          'An email with a verification code has been sent to your email',
      });
    } catch (error) {
      console.log('error when send register email', error);
      await updateUser({ id: user.id }, { verificationCode: undefined });
      return res.status(500).json({
        status: 'error',
        message: 'There was an error sending email, please try again',
      });
    }
  } catch (err) {
    console.log(`Has error at registerUserHandler function`);
    console.log(err);

    if (err instanceof Prisma.PrismaClientKnownRequestError) {
      if (err.code === 'P2002') {
        return res.status(409).json({
          status: 'fail',
          message: 'Email already exist, please use another email address',
        });
      }
    }
    next(err);
  }
};

// Login User Controller
export const loginUserHandler = async (
  req: Request<object, object, LoginUserInput>,
  res: Response,
  next: NextFunction
) => {
  try {
    const { email, password } = req.body;

    const user = await findUniqueUser(
      { email: email.toLocaleLowerCase() },
      { id: true, email: true, verified: true, password: true }
    );

    if (!user) {
      return next(new AppError(400, 'Invalid email or password'));
    }

    // Check if user is verified
    if (!user.verified) {
      return next(
        new AppError(
          401,
          'You are not verified, please verify your email to login'
        )
      );
    }

    if (!(await bcrypt.compare(password, user.password))) {
      return next(new AppError(400, 'Invalid email or password'));
    }

    // Sign Tokens
    const { access_token, refresh_token } = await signTokens(user);

    res.cookie('access_token', access_token, accessTokenCookieOption);
    res.cookie('refresh_token', refresh_token, refreshTokenCookieOptions);
    res.cookie('logged_id', true, {
      ...accessTokenCookieOption,
      httpOnly: false,
    });

    res.status(200).json({
      status: 'success',
      access_token,
    });
  } catch (err) {
    console.log(`Has error at loginUserHandler function`);
    next(err);
  }
};

// Refresh Token
export const refreshAccessToken = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const refreshToken = req.cookies.refresh_token;
    const error_message = 'Invalid refresh token';

    if (!refreshToken) {
      return next(new AppError(403, error_message));
    }

    // Validate refresh_token
    const decoded = verifyJwt<jwt.JwtPayload>(
      refreshToken,
      TokenType.REFRESH_TOKEN_PUBLIC
    );

    if (!decoded) {
      return next(new AppError(403, error_message));
    }

    // Check if user has a valid session
    const session = await redisClient.get(decoded.sub as string);

    if (!session) {
      return next(new AppError(403, error_message));
    }

    // Check if user still exist
    const user = await findUniqueUser({ id: JSON.parse(session).id });

    if (!user) {
      return next(new AppError(403, error_message));
    }

    // Sign new access token
    const access_token = signJwt(
      { sub: user.id },
      TokenType.ACCESS_TOKEN_PRIVATE,
      {
        expiresIn: `${config.get<number>('accessTokenExpiresIn')}m`,
      }
    );

    // 4. Add Cookies
    res.cookie('access_token', access_token, accessTokenCookieOption);
    res.cookie('logged_in', true, {
      ...accessTokenCookieOption,
      httpOnly: false,
    });

    // 5. Send response
    res.status(200).json({
      status: 'success',
      access_token,
    });
  } catch (err) {
    console.log(`Has error at refreshAccessToken function`);
    console.log(err);
    next(err);
  }
};

// Logout Handler
export const logoutUserHandler = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    await redisClient.del(res.locals.user.id);
    res.cookie('access_token', '', { maxAge: -1 });
    res.cookie('refresh_token', '', { maxAge: -1 });
    res.cookie('logged_in', false, { maxAge: -1 });

    res.status(200).json({
      status: 'success',
      message: 'Good bye, see you soon',
    });
  } catch (error) {
    console.log(`Has error at logoutUserHandler function`);
    next(error);
  }
};

// Verify Email Handler
export const verifyEmailHandler = async (
  req: Request<VerifyEmailInput>,
  res: Response,
  next: NextFunction
) => {
  try {
    const verificationCode = crypto
      .createHash('sha256')
      .update(req.params.verificationCode)
      .digest('hex');

    const user = await updateUser(
      { verificationCode },
      { verified: true, verificationCode: undefined },
      { email: true }
    );

    if (!user) {
      return next(new AppError(401, 'Could not verify email'));
    }

    res.status(200).json({
      status: 'success',
      message: 'Email verified successfully',
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } catch (err: any) {
    console.log('Have error on verifyEmailHandler function', err);

    if (err.code === 'P2025') {
      return res.status(403).json({
        status: 'fail',
        message: `Verification code is invalid or user doesn't exist`,
      });
    }
    next(err);
  }
};
