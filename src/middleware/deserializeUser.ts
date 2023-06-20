import { NextFunction, Request, Response } from "express";
import { excludedFields, findUniqueUser } from "../services/user.service";
import { DefaultErrorMessage, TokenType } from "../types";
import redisClient from "../utils/connectRedis";
import AppError from "../utils/handleResponse";
import { verifyJwt } from "../utils/jwt";
import { omit } from "lodash";

export const deserializeUser = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    let access_token;
    // Get access token from header or cookies
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      access_token = req.headers.authorization.split(" ")[1];
    } else if (req.cookies.access_token) {
      access_token = req.cookies.access_token;
    }

    if (!access_token) {
      return next(new AppError(401, DefaultErrorMessage.Unauthorized));
    }

    // After get access token, verify this token
    const decoded = verifyJwt<{ sub: string }>(
      access_token,
      TokenType.ACCESS_TOKEN_PUBLIC
    );

    if (!decoded) {
      return next(new AppError(401, `Invalid token or user doesn't exist`));
    }

    // Check valid session
    const session = await redisClient.get(decoded.sub);

    if (!session) {
      return next(new AppError(401, `Invalid token or session has expired`));
    }

    // Check user exists
    const user = await findUniqueUser({ id: JSON.parse(session).id });

    if (!user) {
      return next(new AppError(401, `Invalid token or session has expired`));
    }

    // Add user to locals
    res.locals.user = omit(user, excludedFields);

    next();
  } catch (error) {
    next(error);
  }
};
