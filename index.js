import dotenv from "dotenv";
dotenv.config({ path: "./.env" });
import cors from "cors";
import express from "express";
import connectDB from "./config/db.js";
import router from "./routes/userRoutes.js";
import errorHandler from "./middleware/errorHandler.js";

const app = express();
app.use(
  cors({
    origin: "http://localhost:3000", // Allow only the frontend URL
    credentials: true, // Allow cookies if used
  })
);

app.use(express.json());
app.use("/", router);
app.use(errorHandler);

connectDB().catch((error) => {
  console.log("DB connection calling failed", error);
});
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`The Server is Running on PORT :${PORT} `);
});
