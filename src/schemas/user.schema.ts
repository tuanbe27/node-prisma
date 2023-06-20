import { RoleEnumType } from "@prisma/client";
import { object, string, TypeOf, z } from "zod";

export const registerUserSchema = object({
  body: object({
    name: string({
      required_error: "Name is required",
    }),
    email: string({
      required_error: "Email address is required",
    }).email("Invalid email address"),
    password: string({
      required_error: "Password is required",
    }).regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,32}$/,
      "assword must be minimum eight characters, at least one uppercase letter, one lowercase letter, one number and one special character"
    ),
    passwordConfirm: string({
      required_error: "Please confirm your password",
    }),
    role: z.optional(z.nativeEnum(RoleEnumType)),
  }).refine((data) => data.password === data.passwordConfirm, {
    path: ["passwordConfirm"],
    message: "Passwords do not match",
  }),
});

export const loginUserSchema = object({
  body: object({
    email: string({ required_error: "Email address is required" }).email(
      "Invalid email address"
    ),
    password: string({ required_error: "Password is required" }).regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,32}$/,
      "Invalid email or password"
    ),
  }),
});

export interface RegisterUserInput
  extends Omit<TypeOf<typeof registerUserSchema>["body"], "passwordConfirm"> {}

export interface LoginUserInput
  extends Omit<TypeOf<typeof loginUserSchema>["body"], ""> {}
