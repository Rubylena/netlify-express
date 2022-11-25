const express = require("express");
const serverless = require("serverless-http");

const app = express();
// const router = express.Router();

require("dotenv/config"); // configure reading from .env
const cors = require("cors");
const {OAuth2Client} = require("google-auth-library");
const jwt = require("jsonwebtoken");

const allowedOrigins = ["http://localhost:5173",
  "https://paddy-journal.netlify.app"];

app.use(
    cors({
        origin: "*",
        methods: "GET,POST,PUT,DELETE,OPTIONS",
      preflightContinue: false,
      optionsSuccessStatus: 204
    }),
);
app.use(express.json());

app.get("/", (request, response) => {
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
app.post("/signup", async (req, res) => {
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
          token: jwt.sign({email: profile?.email}, "mySecret", {
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
app.post("/login", async (req, res) => {
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
          token: jwt.sign({email: profile?.email}, process.env.JWT_SECRET, {
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

module.exports.handler = serverless(app);
