import "express-session";

declare module "express-session" {
  interface SessionData {
    userId: number;
    phone: string;
    role: string;
  }
}
