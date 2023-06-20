import dotenv from "dotenv";
dotenv.config();
import express, { NextFunction, Request, Response } from "express";
import config from "config";
import { PrismaClient } from "@prisma/client";
import cookieParser from "cookie-parser";
import cors from "cors";
import morgan from "morgan";

import redisClient from "./utils/connectRedis";
import validateEnv from "./utils/validateEnv";
import authRouter from "./routes/auth.route";
import userRouter from "./routes/user.route";
import AppError from "./utils/handleResponse";

validateEnv();

const prisma = new PrismaClient();
const app = express();

async function bootstrap() {
  // TEMPLATE ENGINE
  app.set("view engine", "pug");
  app.set("views", `${__dirname}/views`);

  // MIDDLEWARE

  // 1.Body Parser
  app.use(express.json({ limit: "10kb" }));

  // 2. Cookie Parser
  app.use(cookieParser());

  // 3. Cors
  app.use(
    cors({
      origin: [config.get<string>("origin")],
      credentials: true,
    })
  );

  // 4. Logger
  if (process.env.NODE_ENV === "development") app.use(morgan("dev"));

  // ROUTES
  app.use("/api/auth", authRouter);
  app.use("/api/users", userRouter);

  //Testing
  app.get("/api/healthchecker", async (_, res: Response) => {
    const message = await redisClient.get("sayHello");
    res.status(200).json({ status: "success", message });
  });

  // UNHANDLED ROUTES
  app.all("*", (req: Request, res: Response, next: NextFunction) => {
    next(new AppError(404, `Route ${req.originalUrl} not found`));
  });

  // GLOBAL ERROR HANDLER
  app.use((err: AppError, _: Request, res: Response) => {
    err.status = err.status || "error";
    err.statusCode = err.statusCode || 500;

    res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
    });
  });

  const port = config.get<number>("port");
  app.listen(port, () => {
    console.log(`Server on port: ${port}`);
  });
}

bootstrap()
  .catch((err) => {
    throw err;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
