
import express from "express";
import cors from "cors";
import "dotenv/config";
import { MongoClient, ObjectId } from "mongodb";
import Stripe from "stripe";
import { createRemoteJWKSet, jwtVerify } from "jose";

const app = express();
app.use(cors());
app.use(express.json());

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const PORT = process.env.PORT || 5000;

// MongoDB connection
const client = new MongoClient(process.env.MONGODB_URL);

export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.error("MongoDB connection failed:", err);
    throw err;
  }
}

const connectedClient = await connectToMongoDB();
const db = connectedClient.db("wedplan");
const userCollection = db.collection("user");

// ========================================
// JWT Authentication Configuration
// ========================================

const JWKS = createRemoteJWKSet(
  new URL(`${process.env.BETTER_AUTH_URL}/api/auth/jwks`)
);

// ========================================
// 1. Verify Token Middleware
// ========================================

const verifyToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    // Check Authorization Header
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized! Token is missing.",
      });
    }

    // Extract Token
    const token = authHeader.split(" ")[1];

    // Verify JWT
    const { payload } = await jwtVerify(token, JWKS);

    // Get User ID
    const userId = payload.sub;

    if (typeof userId !== "string" || !ObjectId.isValid(userId)) {
      return res.status(401).json({
        success: false,
        message: "Invalid user identity.",
      });
    }

    // Find User from Database
    const loggedInUser = await userCollection.findOne({
      _id: new ObjectId(userId),
    });

    if (!loggedInUser) {
      return res.status(401).json({
        success: false,
        message: "User not found.",
      });
    }

    // Check Blocked User
    if (loggedInUser.isBlocked) {
      return res.status(403).json({
        success: false,
        message: "Your account has been blocked.",
      });
    }

    // Check Valid Role
    if (
      !["admin", "vendor", "customer"].includes(loggedInUser.role)
    ) {
      return res.status(403).json({
        success: false,
        message: "Invalid user role.",
      });
    }

    // Attach User Information to Request
    req.user = {
      id: loggedInUser._id.toString(),
      name: loggedInUser.name,
      email: loggedInUser.email,
      role: loggedInUser.role,
    };

    next();

  } catch (error) {
    console.error("Token verification failed:", error);

    return res.status(401).json({
      success: false,
      message: "Invalid or expired token.",
    });
  }
};

// ========================================
// 2. Verify Admin Middleware
// ========================================

const verifyAdmin = (req, res, next) => {
  if (req.user?.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Admin access denied.",
    });
  }

  next();
};

// ========================================
// 3. Verify Vendor Middleware
// ========================================

const verifyVendor = (req, res, next) => {
  if (req.user?.role !== "vendor") {
    return res.status(403).json({
      success: false,
      message: "Vendor access denied.",
    });
  }

  next();
};

// ========================================
// 4. Verify Customer Middleware
// ========================================

const verifyCustomer = (req, res, next) => {
  if (req.user?.role !== "customer") {
    return res.status(403).json({
      success: false,
      message: "Customer access denied.",
    });
  }

  next();
};

// ========================================
// Test Routes
// ========================================

app.get("/", (req, res) => {
  res.send("Welcome to the WedPlan Server!");
});
// ========================================
// User Related API
// ========================================

// ========================================
// Admin Related API
// ========================================

// ========================================
// Vendor Related API
// ========================================

// ========================================
// Customer Related API
// ========================================

// Admin Test
app.get("/admin", verifyToken, verifyAdmin, (req, res) => {
  res.json({
    success: true,
    message: "Welcome Admin!",
    user: req.user,
  });
});

// Vendor Test
app.get("/vendor", verifyToken, verifyVendor, (req, res) => {
  res.json({
    success: true,
    message: "Welcome Vendor!",
    user: req.user,
  });
});

// Customer Test
app.get("/customer", verifyToken, verifyCustomer, (req, res) => {
  res.json({
    success: true,
    message: "Welcome Customer!",
    user: req.user,
  });
});

// ========================================
// Server Start
// ========================================

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

export default app;
