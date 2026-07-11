import express, { type Express } from "express";
import cors from "cors";
import pinoHttp from "pino-http";
import session from "express-session";
import router from "./routes";
import { logger } from "./lib/logger";

const app: Express = express();

// Trust the Replit reverse proxy so Express sees the real protocol (HTTPS)
// Required for secure cookie handling behind a proxy
app.set("trust proxy", 1);

app.use(
  pinoHttp({
    logger,
    serializers: {
      req(req) {
        return {
          id: req.id,
          method: req.method,
          url: req.url?.split("?")[0],
        };
      },
      res(res) {
        return {
          statusCode: res.statusCode,
        };
      },
    },
  }),
);
app.use(cors({
  origin: true,
  credentials: true,
}));
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) {
  throw new Error("SESSION_SECRET environment variable is required but was not set.");
}

app.use(
  session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      sameSite: "lax",
    },
  }),
);

app.use("/api", router);

// Safety net: any error that reaches here (thrown synchronously, an async
// handler's rejected promise forwarded by Express 5, or a malformed JSON
// body from express.json()) gets a clean JSON response instead of hanging
// the connection or leaking an HTML/stack-trace error page.
app.use(
  (
    err: unknown,
    req: express.Request,
    res: express.Response,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _next: express.NextFunction,
  ) => {
    req.log?.error({ err }, "unhandled request error");
    if (res.headersSent) return;
    res.status(500).json({ error: "Server error" });
  },
);

export default app;
