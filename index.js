import express from "express";
import cors from "cors";
import 'dotenv/config';
import { MongoClient } from 'mongodb';


const app = express();
app.use(cors());
app.use(express.json());
const PORT = process.env.PORT || 5000;

// MongoDB connection
const client = new MongoClient(process.env.MONGODB_URL);

export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.dir(err);
  }
}
const connectedClient = await connectToMongoDB();
const db = connectedClient.db("wedplan");

app.get("/", (req, res) => {
  res.send("Welcome to the WedPlan Server!");
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});