import express, { Router, json } from "express";
import serverless from "serverless-http";

const app = express();
const router = Router();

import 'encoding';
import "dotenv/config"; // configure reading from .env
import cors from "cors";
import { OAuth2Client } from "google-auth-library";
import { sign } from "jsonwebtoken";

const allowedOrigins = ["http://localhost:5173",
  "https://paddy-journal.netlify.app"];

router.use(
    cors({
        origin: "*",
        methods: "GET,POST,PUT,DELETE,OPTIONS",
      preflightContinue: false,
      optionsSuccessStatus: 204
    }),
);
router.use(json());

router.get("/", (request, response) => {
  response.send("Hello Paddy Admin");
});

const DB = [];
/**
 *  This function is used verify a google account
 */
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const client = new OAuth2Client(GOOGLE_CLIENT_ID);


async function verifyGoogleToken(token) {
  try {
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: GOOGLE_CLIENT_ID,
    });
    return {payload: ticket.getPayload()};
  } catch (error) {
    return {error: "Invalid user detected. Please try again"};
  }
}

// sign up
router.post("/signup", async (req, res) => {
  try {
    // console.log({ verified: verifyGoogleToken(req.body.credential) });
    if (req.body.credential) {
      const verificationResponse = await verifyGoogleToken(req.body.credential);

      if (verificationResponse.error) {
        return res.status(400).json({
          message: verificationResponse.error,
        });
      }

      const profile = verificationResponse?.payload;

      DB.push(profile);

      res.status(201).json({
        message: "Signup was successful",
        user: {
          firstName: profile?.given_name,
          lastName: profile?.family_name,
          picture: profile?.picture,
          databaseResponse: DB,
          email: profile?.email,
          token: sign({email: profile?.email}, "mySecret", {
            expiresIn: "1d",
          }),
        },
      });
    }
  } catch (error) {
    res.status(500).json({
      message: "An error occurred. Registration failed.",
    });
  }
});

// login
router.post("/login", async (req, res) => {
  try {
    if (req.body.credential) {
      const verificationResponse = await verifyGoogleToken(req.body.credential);
      if (verificationResponse.error) {
        return res.status(400).json({
          message: verificationResponse.error,
        });
      }

      const profile = verificationResponse?.payload;

      const existsInDB = DB.find((person) => person?.email === profile?.email);

      if (!existsInDB) {
        return res.status(400).json({
          message: "You are not registered. Please sign up",
        });
      }

      res.status(201).json({
        message: "Login was successful",
        user: {
          firstName: profile?.given_name,
          lastName: profile?.family_name,
          databaseResponse: DB,
          picture: profile?.picture,
          email: profile?.email,
          token: sign({email: profile?.email}, process.env.JWT_SECRET, {
            expiresIn: "1d",
          }),
        },
      });
    }
  } catch (error) {
    res.status(500).json({
      message: error?.message || error,
    });
  }
});

app.use("/.netlify/functions/api", router);
export const handler = serverless(app);
