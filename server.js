const express = require("express");
const app = express();
const port = process.env.PORT || 7000;
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

app.use(
  cors({
    origin: [
      /^http:\/\/([a-z0-9-]+\.)*localhost:5173$/i,
      /^http:\/\/([a-z0-9-]+\.)*localhost:3000$/,
      "http://localhost:3000",
      "http://localhost:5173",
    ],
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "126c7e21df539bd70ac72bd3a9e58ec12223865a5e2b6c53901006e334a00686921a0ba0dd453dfba87534151544170f044b89c1ee3e7d2b9438c069f118cbf5";
const COOKIE_DOMAIN = ".localhost";

const uri = `mongodb+srv://hazratalisoft:au6RTwJIIAcx4bG1@cluster0.xrodihi.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const client = new MongoClient(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverApi: ServerApiVersion.v1,
});

const PASSWORD = /^(?=.*[0-9])(?=.*[!@#$%^&*]).{8,}$/;

function shopName(name) {
  return String(name || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "");
}

function signToken(userId, remember) {
  const expiresIn = remember ? "7d" : "30m";
  return jwt.sign({ id: String(userId) }, JWT_SECRET, { expiresIn });
}

function setAuthCookie(res, token, remember) {
  res.cookie("token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: false,
    domain: COOKIE_DOMAIN,
    path: "/",
    maxAge: remember ? 7 * 24 * 60 * 60 * 1000 : 30 * 60 * 1000,
  });
}

async function authMiddleware(req, res, next, usersCollection) {
  const token = req.cookies?.token;
  if (!token) return res.status(401).json({ message: "Unauthorized" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await usersCollection.findOne(
      { _id: new ObjectId(payload.id) },
      { projection: { password: 0 } }
    );
    if (!user) return res.status(401).json({ message: "Unauthorized" });
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

async function run() {
  try {
    await client.connect();
    const db = client.db("userCollection");
    const usersCollection = db.collection("user");
    const shopsCollection = db.collection("shops");
    await usersCollection.createIndex({ username: 1 }, { unique: true });
    await shopsCollection.createIndex({ name: 1 }, { unique: true });

    app.get("/user", async (req, res) => {
      try {
        const cursor = usersCollection.find(
          {},
          { projection: { password: 0 } }
        );
        const users = await cursor.toArray();
        res.send(users);
      } catch (e) {
        res.status(500).json({ message: "Failed to fetch users" });
      }
    });

    //----------------------------- Register ---------------------------
    app.post("/register", async (req, res) => {
      try {
        const { username, password, shops } = req.body || {};
        if (!username || typeof username !== "string") {
          return res.status(400).json({ message: "Username is required" });
        }
        if (!password || !PASSWORD.test(password)) {
          return res.status(400).json({
            message:
              "Password must be at least 8 chars and include a number and a special character",
          });
        }
        if (!Array.isArray(shops) || shops.length < 3) {
          return res
            .status(400)
            .json({ message: "Provide at least 3 shop names" });
        }

        const normalized = shops.map(shopName).filter(Boolean);
        const uniqueSet = new Set(normalized);
        if (uniqueSet.size !== normalized.length) {
          return res.status(400).json({ message: "Shop names must be unique" });
        }
        const existing = await shopsCollection
          .find(
            { name: { $in: normalized } },
            { projection: { _id: 0, name: 1 } }
          )
          .toArray();
        if (existing.length > 0) {
          return res.status(400).json({
            message: `Shop name(s) already exist: ${existing
              .map((s) => s.name)
              .join(", ")}`,
          });
        }
        const usernameTaken = await usersCollection.findOne({
          username: username.toLowerCase(),
        });
        if (usernameTaken) {
          return res.status(400).json({ message: "Username already taken" });
        }
        const hash = await bcrypt.hash(password, 10);
        const userDoc = {
          username: username.toLowerCase(),
          password: hash,
          shops: normalized,
          createdAt: new Date(),
        };
        const userResult = await usersCollection.insertOne(userDoc);
        const shopDocs = normalized.map((n) => ({
          name: n,
          ownerId: userResult.insertedId,
          createdAt: new Date(),
        }));
        await shopsCollection.insertMany(shopDocs);

        return res
          .status(201)
          .json({ message: "User registered successfully" });
      } catch (err) {
        if (err?.code === 11000) {
          const key = Object.keys(err.keyPattern || {})[0] || "field";
          return res.status(400).json({ message: `Duplicate ${key}` });
        }
        console.error("Signup error:", err);
        return res.status(500).json({ message: "Server error" });
      }
    });

    // ------------------------------- Login -----------------------------------

    app.post("/login", async (req, res) => {
      try {
        const { username, password, remember } = req.body || {};
        if (!username || !password) {
          return res
            .status(400)
            .json({ message: "Username and password are required" });
        }

        const user = await usersCollection.findOne({
          username: String(username).toLowerCase(),
        });
        if (!user) return res.status(404).json({ message: "User not found" });

        const ok = await bcrypt.compare(password, user.password);
        if (!ok) return res.status(400).json({ message: "Incorrect password" });

        const token = signToken(user._id, !!remember);
        setAuthCookie(res, token, !!remember);

        return res.json({ message: "Login successful" });
      } catch (err) {
        console.error("Login error:", err);
        return res.status(500).json({ message: "Server error" });
      }
    });

    app.get("/dashboard", (req, res) => {
      authMiddleware(
        req,
        res,
        async () => {
          res.json({ username: req.user.username, shops: req.user.shops });
        },
        usersCollection
      );
    });

    //------------------------------ Shop details --------------------------
    app.get("/shop/:shopName", async (req, res) => {
      const { shopName } = req.params;
      const shop = await shopsCollection.findOne({ name: shopName });
      if (!shop) return res.status(404).json({ message: "Shop not found" });

      const owner = await usersCollection.findOne({ _id: shop.ownerId });
      res.json({
        name: shop.name,
        mobile: shop.mobile,
        owner: owner?.username,
      });
    });

    // ----------------------- Logout ---------------------------
    app.post("/logout", (req, res) => {
      res.clearCookie("token", {
        httpOnly: true,
        sameSite: "lax",
        secure: false,
        domain: COOKIE_DOMAIN,
        path: "/",
      });
      res.json({ message: "Logged out" });
    });
  } finally {
  }
}
run().catch(console.dir);
app.get("/", (req, res) => {
  res.send("Alhamdulliah Your server is Running");
});
app.listen(port, () => {
  console.log("Alhamdullilah Your server is Start");
});
