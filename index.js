
import express from "express";
import cors from "cors";
import "dotenv/config";
import { MongoClient, ObjectId } from "mongodb";
import Stripe from "stripe";
import { createRemoteJWKSet, jwtVerify } from "jose";

const app = express();
const CLIENT_ORIGIN = process.env.CLIENT_URL || "http://localhost:3000";
app.use(cors({ origin: CLIENT_ORIGIN, credentials: true }));
app.use(express.json({ limit: "1mb" }));

const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY)
  : null;
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
const servicesCollection = db.collection("services");
const bookingsCollection = db.collection("bookings");
const transactionsCollection = db.collection("transactions");

await servicesCollection.createIndex({ vendorId: 1, createdAt: -1 });
await servicesCollection.createIndex({ status: 1, isActive: 1 });
await bookingsCollection.createIndex({ vendorId: 1, status: 1, createdAt: -1 });
await bookingsCollection.createIndex({ customerId: 1, createdAt: -1 });
await bookingsCollection.createIndex({ serviceId: 1 });
await transactionsCollection.createIndex({ bookingId: 1, createdAt: -1 });

// ========================================
// JWT Authentication Configuration
// ========================================

const JWKS = createRemoteJWKSet(
  new URL(`${process.env.BETTER_AUTH_URL}/api/auth/jwks`)
);

// The client's jwt() plugin must sign with these same values.
const jwtVerifyOptions = {
  algorithms: ["EdDSA"],
  ...(process.env.JWT_ISSUER ? { issuer: process.env.JWT_ISSUER } : {}),
  ...(process.env.JWT_AUDIENCE ? { audience: process.env.JWT_AUDIENCE } : {}),
};

// ========================================
// 1. Verify Token Middleware
// ========================================

const verifyToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const match =
      typeof authHeader === "string"
        ? authHeader.match(/^Bearer\s+(\S+)$/i)
        : null;

    if (!match) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized! Token is missing.",
      });
    }

    // Verify JWT — issuer, audience and algorithm are all checked.
    let payload;
    try {
      ({ payload } = await jwtVerify(match[1], JWKS, jwtVerifyOptions));
    } catch (error) {
      console.error("Token verification failed:", error);
      return res.status(401).json({
        success: false,
        message: "Invalid or expired token.",
      });
    }

    const userId = payload.sub;

    if (typeof userId !== "string" || !ObjectId.isValid(userId)) {
      return res.status(401).json({
        success: false,
        message: "Invalid user identity.",
      });
    }

    try {
      const loggedInUser = await userCollection.findOne({
        _id: new ObjectId(userId),
      });

      if (!loggedInUser) {
        return res.status(401).json({
          success: false,
          message: "User not found.",
        });
      }

      if (loggedInUser.isBlocked) {
        return res.status(403).json({
          success: false,
          message: "Your account has been blocked.",
        });
      }

      if (!["admin", "vendor", "customer"].includes(loggedInUser.role)) {
        return res.status(403).json({
          success: false,
          message: "Invalid user role.",
        });
      }

      req.user = {
        id: loggedInUser._id.toString(),
        name: loggedInUser.name,
        email: loggedInUser.email,
        role: loggedInUser.role,
        subscriptionPlan: loggedInUser.subscriptionPlan ?? "free",
      };
    } catch (error) {
      console.error("User lookup failed:", error);
      return res.status(500).json({
        success: false,
        message: "Could not verify your account. Please try again.",
      });
    }

    next();
  } catch (error) {
    console.error("Authentication failed:", error);
    return res.status(500).json({
      success: false,
      message: "Could not authenticate the request.",
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
const MAX_SERVICE_IMAGES = 3;
const SERVICE_CATEGORIES = [
  "Photography & Videography",
  "Venue & Decoration",
  "Catering & Cake",
  "Bridal & Grooming",
  "Music & Entertainment",
  "Wedding Planning",
  "Transport & Logistics",
  "Other",
];

function serializeService(service) {
  const { _id, ...rest } = service;
  return {
    ...rest,
    id: _id.toString(),
    vendorId: service.vendorId.toString(),
  };
}

async function withVendorInfo(service) {
  const vendor = await userCollection.findOne(
    { _id: service.vendorId },
    { projection: { name: 1, businessName: 1, image: 1 } }
  );

  return {
    ...serializeService(service),
    vendor: vendor
      ? {
          name: vendor.name ?? null,
          businessName: vendor.businessName ?? null,
          image: vendor.image ?? null,
        }
      : null,
  };
}

function isHttpUrl(value) {
  try {
    return ["http:", "https:"].includes(new URL(value).protocol);
  } catch {
    return false;
  }
}

function validateServicePayload(body) {
  const errors = [];
  const serviceName =
    typeof body.serviceName === "string" ? body.serviceName.trim() : "";
  const category = typeof body.category === "string" ? body.category.trim() : "";
  const description =
    typeof body.description === "string" ? body.description.trim() : "";
  const location = typeof body.location === "string" ? body.location.trim() : "";
  const rawPrice = body.price;
  const price = typeof rawPrice === "string" ? Number(rawPrice) : rawPrice;
  const images = Array.isArray(body.images) ? body.images : [];

  if (!serviceName) errors.push("Service name is required.");
  else if (serviceName.length > 120)
    errors.push("Service name must be 120 characters or fewer.");

  if (!category) errors.push("Service category is required.");
  else if (!SERVICE_CATEGORIES.includes(category))
    errors.push("Choose a valid service category.");

  if (!description) errors.push("Description is required.");
  else if (description.length < 20)
    errors.push("Description must be at least 20 characters.");
  else if (description.length > 2000)
    errors.push("Description must be 2000 characters or fewer.");

  if (!location) errors.push("Location is required.");
  else if (location.length > 120)
    errors.push("Location must be 120 characters or fewer.");

  if (typeof price !== "number" || !Number.isFinite(price) || price <= 0)
    errors.push("Price must be a positive number.");
  else if (price > 100000000)
    errors.push("Price is out of range.");

  if (images.length === 0) errors.push("At least one service image is required.");
  else if (images.length > MAX_SERVICE_IMAGES)
    errors.push(`You can upload up to ${MAX_SERVICE_IMAGES} images.`);
  else if (!images.every((image) => typeof image === "string" && isHttpUrl(image)))
    errors.push("Every image must be a valid image URL.");

  return {
    errors,
    value: { serviceName, category, description, location, price, images },
  };
}

const FREE_PLAN_ACTIVE_LIMIT = 3;

function serializeBooking(booking) {
  const { _id, ...rest } = booking;
  return {
    ...rest,
    id: _id.toString(),
    serviceId: booking.serviceId.toString(),
    vendorId: booking.vendorId.toString(),
    customerId: booking.customerId.toString(),
  };
}

function isPremium(user) {
  return user?.subscriptionPlan === "premium";
}

async function countActiveServices(vendorId) {
  return servicesCollection.countDocuments({
    vendorId: new ObjectId(vendorId),
    status: "approved",
    isActive: true,
  });
}

function validateBookingPayload(body) {
  const errors = [];
  const serviceId = typeof body.serviceId === "string" ? body.serviceId.trim() : "";
  const eventLocation =
    typeof body.eventLocation === "string" ? body.eventLocation.trim() : "";
  const message = typeof body.message === "string" ? body.message.trim() : "";
  const rawDate = body.eventDate;
  const eventDate = new Date(rawDate);
  const validDate =
    typeof rawDate === "string" && !Number.isNaN(eventDate.getTime());

  if (!ObjectId.isValid(serviceId)) errors.push("A valid service is required.");
  if (!validDate) errors.push("A valid event date is required.");
  if (!eventLocation) errors.push("Event location is required.");
  else if (eventLocation.length > 160)
    errors.push("Event location must be 160 characters or fewer.");
  if (!message) errors.push("A message for the vendor is required.");
  else if (message.length > 1000)
    errors.push("Message must be 1000 characters or fewer.");

  return {
    errors,
    value: { serviceId, eventDate, eventLocation, message },
  };
}

// Create a service — pending admin approval by default
app.post("/add-service", verifyToken, verifyVendor, async (req, res) => {
  try {
    const { errors, value } = validateServicePayload(req.body ?? {});

    if (errors.length > 0) {
      return res.status(400).json({
        success: false,
        message: "Please check the submitted fields.",
        errors,
      });
    }

    if (!isPremium(req.user)) {
      const activeCount = await countActiveServices(req.user.id);
      if (activeCount >= FREE_PLAN_ACTIVE_LIMIT) {
        return res.status(403).json({
          success: false,
          message: `Free plan allows up to ${FREE_PLAN_ACTIVE_LIMIT} active services. Upgrade to Premium to publish more.`,
        });
      }
    }

    const now = new Date();
    const service = {
      vendorId: new ObjectId(req.user.id),
      serviceName: value.serviceName,
      category: value.category,
      description: value.description,
      price: value.price,
      location: value.location,
      images: value.images,
      status: "pending",
      isActive: true,
      createdAt: now,
      updatedAt: now,
    };

    const result = await servicesCollection.insertOne(service);

    return res.status(201).json({
      success: true,
      message: "Service submitted successfully. It is now pending admin approval.",
      service: serializeService({ ...service, _id: result.insertedId }),
    });
  } catch (error) {
    console.error("Create service failed:", error);
    return res.status(500).json({
      success: false,
      message: "Could not submit your service. Please try again.",
    });
  }
});

// Vendor's own services with approval status
app.get("/my-services", verifyToken, verifyVendor, async (req, res) => {
  try {
    const services = await servicesCollection
      .find({ vendorId: new ObjectId(req.user.id) })
      .sort({ createdAt: -1 })
      .toArray();

    return res.json({
      success: true,
      services: services.map(serializeService),
    });
  } catch (error) {
    console.error("Fetch vendor services failed:", error);
    return res.status(500).json({
      success: false,
      message: "Could not load your services. Please try again.",
    });
  }
});

// Vendor overview counters
app.get("/vendor/stats", verifyToken, verifyVendor, async (req, res) => {
  try {
    const vendorId = new ObjectId(req.user.id);

    const [totalServices, activeServices, pendingBookings, acceptedBookings] =
      await Promise.all([
        servicesCollection.countDocuments({ vendorId }),
        countActiveServices(req.user.id),
        bookingsCollection.countDocuments({ vendorId, status: "pending" }),
        bookingsCollection.countDocuments({ vendorId, status: "accepted" }),
      ]);

    return res.json({
      success: true,
      stats: {
        totalServices,
        activeServices,
        pendingBookings,
        acceptedBookings,
        subscriptionPlan: isPremium(req.user) ? "premium" : "free",
        activeServiceLimit: isPremium(req.user) ? null : FREE_PLAN_ACTIVE_LIMIT,
      },
    });
  } catch (error) {
    console.error("Fetch vendor stats failed:", error);
    return res.status(500).json({
      success: false,
      message: "Could not load your dashboard. Please try again.",
    });
  }
});

// Single owned service (used by the edit form)
app.get("/vendor/services/:id", verifyToken, verifyVendor, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: "Invalid service id." });
    }

    const service = await servicesCollection.findOne({
      _id: new ObjectId(id),
      vendorId: new ObjectId(req.user.id),
    });

    if (!service) {
      return res.status(404).json({ success: false, message: "Service not found." });
    }

    return res.json({ success: true, service: serializeService(service) });
  } catch (error) {
    console.error("Fetch service failed:", error);
    return res.status(500).json({
      success: false,
      message: "Could not load the service. Please try again.",
    });
  }
});

// Update an owned service (never changes status/approval)
app.patch("/vendor/services/:id", verifyToken, verifyVendor, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: "Invalid service id." });
    }

    const { errors, value } = validateServicePayload(req.body ?? {});
    if (errors.length > 0) {
      return res.status(400).json({
        success: false,
        message: "Please check the submitted fields.",
        errors,
      });
    }

    const result = await servicesCollection.findOneAndUpdate(
      { _id: new ObjectId(id), vendorId: new ObjectId(req.user.id) },
      {
        $set: {
          ...value,
          updatedAt: new Date(),
        },
      },
      { returnDocument: "after" }
    );

    if (!result) {
      return res.status(404).json({ success: false, message: "Service not found." });
    }

    return res.json({
      success: true,
      message: "Service updated successfully.",
      service: serializeService(result),
    });
  } catch (error) {
    console.error("Update service failed:", error);
    return res.status(500).json({
      success: false,
      message: "Could not update the service. Please try again.",
    });
  }
});

// Delete an owned service (and its booking requests)
app.delete("/vendor/services/:id", verifyToken, verifyVendor, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: "Invalid service id." });
    }

    const objectId = new ObjectId(id);
    const result = await servicesCollection.deleteOne({
      _id: objectId,
      vendorId: new ObjectId(req.user.id),
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, message: "Service not found." });
    }

    await bookingsCollection.deleteMany({ serviceId: objectId });

    return res.json({ success: true, message: "Service deleted." });
  } catch (error) {
    console.error("Delete service failed:", error);
    return res.status(500).json({
      success: false,
      message: "Could not delete the service. Please try again.",
    });
  }
});

// Manage availability of an owned service
app.patch(
  "/vendor/services/:id/availability",
  verifyToken,
  verifyVendor,
  async (req, res) => {
    try {
      const { id } = req.params;
      const isActive = req.body?.isActive;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ success: false, message: "Invalid service id." });
      }
      if (typeof isActive !== "boolean") {
        return res.status(400).json({
          success: false,
          message: "isActive must be a boolean.",
        });
      }

      const service = await servicesCollection.findOne({
        _id: new ObjectId(id),
        vendorId: new ObjectId(req.user.id),
      });

      if (!service) {
        return res.status(404).json({ success: false, message: "Service not found." });
      }

      if (isActive && !service.isActive && !isPremium(req.user)) {
        const activeCount = await countActiveServices(req.user.id);
        if (activeCount >= FREE_PLAN_ACTIVE_LIMIT) {
          return res.status(403).json({
            success: false,
            message: `Free plan allows up to ${FREE_PLAN_ACTIVE_LIMIT} active services. Upgrade to Premium to publish more.`,
          });
        }
      }

      const result = await servicesCollection.findOneAndUpdate(
        { _id: new ObjectId(id), vendorId: new ObjectId(req.user.id) },
        { $set: { isActive, updatedAt: new Date() } },
        { returnDocument: "after" }
      );

      return res.json({
        success: true,
        message: isActive ? "Service is now active." : "Service is now inactive.",
        service: serializeService(result),
      });
    } catch (error) {
      console.error("Update availability failed:", error);
      return res.status(500).json({
        success: false,
        message: "Could not update availability. Please try again.",
      });
    }
  }
);

// Vendor booking requests — only this vendor's bookings
app.get("/vendor/bookings", verifyToken, verifyVendor, async (req, res) => {
  try {
    const bookings = await bookingsCollection
      .find({ vendorId: new ObjectId(req.user.id) })
      .sort({ createdAt: -1 })
      .toArray();

    return res.json({
      success: true,
      bookings: bookings.map(serializeBooking),
    });
  } catch (error) {
    console.error("Fetch vendor bookings failed:", error);
    return res.status(500).json({
      success: false,
      message: "Could not load booking requests. Please try again.",
    });
  }
});

// Accept / reject — atomic, pending-only, and scoped to the owning vendor.
// The filter makes double-processing and cross-vendor changes impossible.
app.patch(
  "/vendor/bookings/:id/status",
  verifyToken,
  verifyVendor,
  async (req, res) => {
    try {
      const { id } = req.params;
      const status = req.body?.status;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ success: false, message: "Invalid booking id." });
      }
      if (!["accepted", "rejected"].includes(status)) {
        return res.status(400).json({
          success: false,
          message: "Status must be accepted or rejected.",
        });
      }

      const result = await bookingsCollection.findOneAndUpdate(
        {
          _id: new ObjectId(id),
          vendorId: new ObjectId(req.user.id),
          status: "pending",
        },
        { $set: { status, updatedAt: new Date() } },
        { returnDocument: "after" }
      );

      if (!result) {
        return res.status(409).json({
          success: false,
          message: "This request was not found or has already been processed.",
        });
      }

      return res.json({
        success: true,
        message: `Booking ${status}.`,
        booking: serializeBooking(result),
      });
    } catch (error) {
      console.error("Update booking status failed:", error);
      return res.status(500).json({
        success: false,
        message: "Could not update the request. Please try again.",
      });
    }
  }
);

// Admin moderation: every service, newest first
app.get("/admin/services", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const services = await servicesCollection
      .find({})
      .sort({ createdAt: -1 })
      .toArray();

    return res.json({
      success: true,
      services: services.map(serializeService),
    });
  } catch (error) {
    console.error("Fetch admin services failed:", error);
    return res.status(500).json({
      success: false,
      message: "Could not load services. Please try again.",
    });
  }
});

app.patch(
  "/admin/services/:id/status",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const status = req.body?.status;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid service id.",
        });
      }

      if (!["approved", "rejected", "pending"].includes(status)) {
        return res.status(400).json({
          success: false,
          message: "Status must be approved, rejected or pending.",
        });
      }

      // Read the current state BEFORE updating — after the update the
      // document already has the new status.
      const existing = await servicesCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!existing) {
        return res.status(404).json({
          success: false,
          message: "Service not found.",
        });
      }

      // Do not let approval bypass the vendor's free-plan limit.
      if (status === "approved" && existing.status !== "approved") {
        const vendor = await userCollection.findOne({ _id: existing.vendorId });
        if (vendor?.subscriptionPlan !== "premium") {
          const activeCount = await countActiveServices(
            existing.vendorId.toString()
          );
          if (activeCount >= FREE_PLAN_ACTIVE_LIMIT) {
            return res.status(409).json({
              success: false,
              message: `This vendor already has ${FREE_PLAN_ACTIVE_LIMIT} active services on the free plan.`,
            });
          }
        }
      }

      const result = await servicesCollection.findOneAndUpdate(
        { _id: new ObjectId(id) },
        { $set: { status, updatedAt: new Date() } },
        { returnDocument: "after" }
      );

      return res.json({
        success: true,
        message: `Service ${status} successfully.`,
        service: serializeService(result),
      });
    } catch (error) {
      console.error("Update service status failed:", error);
      return res.status(500).json({
        success: false,
        message: "Could not update the service. Please try again.",
      });
    }
  }
);

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Public discovery: only approved, active services.
// Search, category and location filtering all happen here in the database.
app.get("/services", async (req, res) => {
  try {
    const queryValue = (key) =>
      typeof req.query[key] === "string" ? req.query[key].trim() : "";

    const search = queryValue("search");
    const location = queryValue("location");
    const requestedCategory = queryValue("category");

    // Show everything vendors have published except rejected services.
    // Pending listings are visible but cannot be booked until approved.
    const filter = { status: { $in: ["pending", "approved"] }, isActive: true };

    if (search) {
      filter.serviceName = { $regex: escapeRegex(search), $options: "i" };
    }
    if (SERVICE_CATEGORIES.includes(requestedCategory)) {
      filter.category = requestedCategory;
    }
    if (location) {
      filter.location = { $regex: escapeRegex(location), $options: "i" };
    }

    const services = await servicesCollection
      .find(filter)
      .sort({ createdAt: -1 })
      .limit(50)
      .toArray();

    return res.json({
      success: true,
      services: await Promise.all(services.map(withVendorInfo)),
    });
  } catch (error) {
    console.error("Fetch public services failed:", error);
    return res.status(500).json({
      success: false,
      message: "Could not load services. Please try again.",
    });
  }
});

// Public service detail — rejected and paused services stay hidden
app.get("/services/:id", async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: "Invalid service id." });
    }

    const service = await servicesCollection.findOne({
      _id: new ObjectId(id),
      status: { $in: ["pending", "approved"] },
      isActive: true,
    });

    if (!service) {
      return res.status(404).json({
        success: false,
        message: "Service not found or no longer available.",
      });
    }

    return res.json({ success: true, service: await withVendorInfo(service) });
  } catch (error) {
    console.error("Fetch public service failed:", error);
    return res.status(500).json({
      success: false,
      message: "Could not load the service. Please try again.",
    });
  }
});

// ========================================
// Customer Related API
// ========================================

// Create a booking request for an approved, active service
app.post("/bookings", verifyToken, verifyCustomer, async (req, res) => {
  try {
    const { errors, value } = validateBookingPayload(req.body ?? {});
    if (errors.length > 0) {
      return res.status(400).json({
        success: false,
        message: "Please check the submitted fields.",
        errors,
      });
    }

    const service = await servicesCollection.findOne({
      _id: new ObjectId(value.serviceId),
      status: "approved",
      isActive: true,
    });

    if (!service) {
      return res.status(404).json({
        success: false,
        message: "This service is not available for booking.",
      });
    }

    if (
      req.user.role === "vendor" &&
      service.vendorId.toString() === req.user.id
    ) {
      return res.status(403).json({
        success: false,
        message: "You cannot book your own service.",
      });
    }

    const now = new Date();
    const booking = {
      serviceId: service._id,
      vendorId: service.vendorId,
      customerId: new ObjectId(req.user.id),
      customerName: req.user.name,
      customerEmail: req.user.email,
      serviceName: service.serviceName,
      serviceImage: service.images?.[0] ?? null,
      price: service.price,
      eventDate: value.eventDate,
      eventLocation: value.eventLocation,
      message: value.message,
      status: "pending",
      createdAt: now,
      updatedAt: now,
    };

    const result = await bookingsCollection.insertOne(booking);

    return res.status(201).json({
      success: true,
      message: "Booking request sent successfully.",
      booking: serializeBooking({ ...booking, _id: result.insertedId }),
    });
  } catch (error) {
    console.error("Create booking failed:", error);
    return res.status(500).json({
      success: false,
      message: "Could not send your booking request. Please try again.",
    });
  }
});

// Customer's own booking requests
app.get("/customer/bookings", verifyToken, verifyCustomer, async (req, res) => {
  try {
    const bookings = await bookingsCollection
      .find({ customerId: new ObjectId(req.user.id) })
      .sort({ createdAt: -1 })
      .toArray();

    return res.json({
      success: true,
      bookings: bookings.map(serializeBooking),
    });
  } catch (error) {
    console.error("Fetch customer bookings failed:", error);
    return res.status(500).json({
      success: false,
      message: "Could not load your bookings. Please try again.",
    });
  }
});

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
// Fallback error / 404 handlers
// ========================================

app.use((req, res) => {
  return res.status(404).json({
    success: false,
    message: "Route not found.",
  });
});

app.use((error, req, res, next) => {
  console.error("Unhandled server error:", error);

  if (error?.type === "entity.parse.failed") {
    return res.status(400).json({
      success: false,
      message: "Invalid JSON body.",
    });
  }

  return res.status(500).json({
    success: false,
    message: "Something went wrong. Please try again.",
  });
});

// ========================================
// Server Start
// ========================================

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

export default app;
