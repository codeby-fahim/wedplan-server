# WedPlan — API Server

[![Node.js](https://img.shields.io/badge/Node.js-20%2B-green?logo=node.js)](https://nodejs.org/)
[![Express](https://img.shields.io/badge/Express-5-black?logo=express)](https://expressjs.com/)
[![MongoDB](https://img.shields.io/badge/MongoDB-7.9-green?logo=mongodb)](https://www.mongodb.com/)
[![Stripe](https://img.shields.io/badge/Payments-Stripe-635bff?logo=stripe)](https://stripe.com/)
[![JWT](https://img.shields.io/badge/Auth-JWKS%20JWT-orange)](https://jose.readthedocs.io/)

Express REST API for **WedPlan**. It handles vendor services, customer bookings, admin moderation and Stripe subscription payments. Authentication is delegated to Better Auth on the Next.js client; this server verifies the issued JWTs against the client's JWKS endpoint.

| Resource | Link |
| --- | --- |
| 🚀 Live API | [wedplan-server-kohl.vercel.app](https://wedplan-server-kohl.vercel.app) |
| 📦 Source code | [github.com/codeby-fahim/wedplan-server](https://github.com/codeby-fahim/wedplan-server.git) |
| 🌐 Client app | [wedplan-client-eta.vercel.app](https://wedplan-client-eta.vercel.app) |
| 📦 Client source | [github.com/codeby-fahim/wedplan-client](https://github.com/codeby-fahim/wedplan-client.git) |

---

## Features

- JWT authentication using a remote JWKS, with pinned **issuer**, **audience** and **algorithm**
- Role middleware for `admin`, `vendor` and `customer`; blocked accounts are rejected on every private route
- Ownership checks on every service and booking mutation
- Service publishing with approval workflow (`pending` → `approved` / `rejected`)
- Free-plan limit of 3 services; Premium vendors are unlimited
- Booking requests with atomic accept/reject/cancel and duplicate prevention
- Stripe Checkout sessions and webhook-driven subscription activation, cancellation and recovery
- Read-only transaction records — no endpoint can alter a payment result
- Admin user search/filter, block/unblock, service moderation and platform statistics
- Server-side validation, escaped regex searches, strict ObjectId checks, and safe error handling

---

## Tech stack

| Layer | Technology |
| --- | --- |
| Runtime | Node.js 20+ (ES modules) |
| Framework | Express 5 |
| Database | MongoDB with the official Node driver 7 |
| Auth | `jose` — remote JWKS + JWT verification |
| Payments | Stripe SDK (Checkout + webhooks) |
| Configuration | `dotenv` |

---

## Getting started

```bash
git clone https://github.com/codeby-fahim/wedplan-server.git
cd wedplan-server
npm install
cp .env.example .env
npm start        # http://localhost:5000
```

Use `npm run dev` for auto-restart on file changes.

### Environment variables

| Variable | Description |
| --- | --- |
| `PORT` | Server port (default `5000`) |
| `MONGODB_URL` | MongoDB Atlas connection string |
| `CLIENT_URL` | Client origin — used for CORS and Stripe return URLs |
| `BETTER_AUTH_URL` | **Client** origin — the server fetches `${BETTER_AUTH_URL}/api/auth/jwks` |
| `STRIPE_SECRET_KEY` | Stripe sandbox (`sk_test_…`) or live (`sk_live_…`) key |
| `STRIPE_PREMIUM_PRICE_ID` | Recurring Stripe Price ID for the Premium plan |
| `STRIPE_WEBHOOK_SECRET` | Signing secret from the Stripe Dashboard webhook endpoint |
| `JWT_ISSUER` / `JWT_AUDIENCE` | Must match the client's `jwt()` configuration |

---

## Data model

Better Auth manages its own `user`, `account`, `session` and `verification` collections. The application uses these business collections:

| Collection | Purpose |
| --- | --- |
| `services` | Vendor services with `vendorId`, `images`, `status`, `isActive` |
| `bookings` | Customer requests with `serviceId`, `vendorId`, `customerId`, `eventDate`, `status` |
| `transactions` | Premium payment records with `vendorId`, `plan`, `amount`, `currency`, Stripe IDs and `status` |

---

## API reference

All private endpoints require `Authorization: Bearer <JWT>` obtained from the client's Better Auth `/api/auth/token` endpoint.

### Public

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | `/` | Health check |
| GET | `/services` | Approved + active services; `search`, `category`, `location`, `sort=price_asc\|price_desc` |
| GET | `/services/:id` | Approved + active service detail |
| GET | `/featured-services` | Up to 6 approved + active services |
| POST | `/webhooks/stripe` | Stripe webhook (raw body, signature verified) |

### Vendor

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | `/vendor/stats` | Dashboard counters |
| GET | `/my-services` | Own services |
| POST | `/add-service` | Create a service (pending) |
| GET/PATCH/DELETE | `/vendor/services/:id` | View, update or delete an owned service |
| PATCH | `/vendor/services/:id/availability` | Pause or reactivate a service |
| GET | `/vendor/bookings` | Bookings for own services |
| PATCH | `/vendor/bookings/:id/status` | Accept or reject a pending request |
| POST | `/vendor/subscription/checkout` | Create a Stripe Checkout session |
| POST | `/vendor/subscription/confirm` | Verify a paid session with Stripe directly |
| GET | `/vendor/subscription/status` | Read-only plan + transaction status |

### Customer

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | `/customer/stats` | Dashboard counters |
| GET | `/customer/bookings` | Own booking requests |
| POST | `/bookings` | Create a request for an approved + active service |
| DELETE | `/customer/bookings/:id/cancel` | Delete a pending request |

### Admin

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | `/admin/stats` | Platform counters |
| GET | `/admin/users` | Users; `search`, `role` filters |
| PATCH | `/admin/users/:id/block` | Block or unblock a user |
| GET | `/admin/services` | All services; `search`, `category`, `status`, `location` filters |
| PATCH | `/admin/services/:id/status` | Approve, reject or reset a service |
| DELETE | `/admin/services/:id` | Delete a service and its bookings |
| GET | `/admin/transactions` | Read-only payment records |

---

## Stripe webhook events

Register `https://<api-domain>/webhooks/stripe` in Stripe with:

- `checkout.session.completed`
- `customer.subscription.deleted`
- `customer.subscription.updated`
- `invoice.payment_failed`

Webhook mode (test/live) must match the configured secret key and Price ID. The signing secret must come from that exact Dashboard endpoint.

---

## Security design

- JWTs are verified with `jose` against a remote JWKS; missing issuer/audience env values fall back to the same constants the client signs with, so verification never silently degrades.
- User identity and role come from the verified token **and** a fresh database lookup — never from request bodies.
- Stripe webhooks are verified against the raw request body before any parsing.
- Plan activation is only possible from a verified webhook or server-side Stripe retrieval; browser redirects have no authority.
- Regex inputs are escaped; query and body values are type-checked; ObjectIds must be strict 24-character hex.
- Index creation is failure-tolerant so legacy data cannot prevent startup.
- A JSON 404 handler and centralized error handler prevent HTML error pages.

---

## Deployment

The project includes a `vercel.json` that builds `index.js` as a Vercel serverless function and routes all paths to it. `app.listen()` is skipped when `VERCEL` is set.

For long-running hosts, simply run `npm start` and expose the configured `PORT`.

Ensure MongoDB Atlas allows connections from the hosting provider and that `CLIENT_URL` / `BETTER_AUTH_URL` point at the deployed client origin.

---

## Scripts

| Command | Description |
| --- | --- |
| `npm start` | Start the production server |
| `npm run dev` | Start with auto-reload |
| `npm test` | Placeholder test script |

---

## License

MIT — built for demonstration and evaluation purposes.
