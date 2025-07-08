import dotenv from "dotenv";
dotenv.config();

import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import type { Express } from "express";
import { storage } from "./storage";

// 환경변수에서 클라이언트 ID/시크릿을 안전하게 불러옴
const clientID = process.env.GOOGLE_CLIENT_ID as string;
const clientSecret = process.env.GOOGLE_CLIENT_SECRET as string;

export function setupGoogleAuth(app: Express) {
  // 구글 OAuth 전략 설정
  passport.use(
    new GoogleStrategy(
      {
        clientID,
        clientSecret,
        callbackURL: "/api/auth/google/callback",
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          // 사용자 정보 추출
          const userData = {
            id: profile.id,
            email: profile.emails?.[0]?.value || "",
            firstName: profile.name?.givenName || "",
            lastName: profile.name?.familyName || "",
            profileImageUrl: profile.photos?.[0]?.value || "",
          };

          // 데이터베이스에 사용자 정보 저장/업데이트
          const user = await storage.upsertUser(userData);
          return done(null, user);
        } catch (error) {
          console.error("Google OAuth error:", error);
          return done(error, false);
        }
      },
    ),
  );

  // 세션 직렬화
  passport.serializeUser((user: any, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id: string, done) => {
    try {
      const user = await storage.getUser(id);
      done(null, user);
    } catch (error) {
      done(error, null);
    }
  });

  // 미들웨어 설정
  app.use(passport.initialize());
  app.use(passport.session());

  // 구글 로그인 라우트
  app.get(
    "/api/auth/google",
    passport.authenticate("google", {
      scope: ["profile", "email"],
    }),
  );

  // 구글 콜백 라우트
  app.get(
    "/api/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/login" }),
    (req, res) => {
      res.redirect("/");
    },
  );

  // 로그아웃 라우트
  app.post("/api/auth/logout", (req, res) => {
    req.logout((err) => {
      if (err) {
        return res.status(500).json({ error: "로그아웃 실패" });
      }
      req.session.destroy((err) => {
        if (err) {
          return res.status(500).json({ error: "세션 삭제 실패" });
        }
        res.json({ success: true, message: "로그아웃 완료" });
      });
    });
  });

  // 사용자 정보 조회 라우트
  app.get("/api/auth/user", (req, res) => {
    if (req.isAuthenticated() && req.user) {
      res.json(req.user);
    } else {
      res.status(401).json({ message: "Unauthorized" });
    }
  });

  console.log("Google OAuth setup completed");
}
