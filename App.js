const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// Load environment variables
dotenv.config();

// Check for JWT_SECRET
if (!process.env.JWT_SECRET) {
  console.error("⚠️  JWT_SECRET is not defined in .env file!");
  process.exit(1);
}

const app = express();
app.use(cors());
app.use(express.json()); // To parse JSON requests

// MongoDB connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => {
    console.error("❌ Failed to connect to MongoDB:", err.message);
    process.exit(1);
  });

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  roles: { type: [String], default: ["ROLE_USER"] },
});

const User = mongoose.model("User", userSchema);

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers["x-access-token"];
  if (!token) return res.status(403).send({ message: "No token provided!" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).send({ message: "Unauthorized access!" });
    req.userId = decoded.id;
    next();
  });
};

// Register Route
app.post("/api/auth/signup", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).send({ message: "All fields are required!" });
  }

  try {
    // Case-insensitive email check
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).send({ message: "Email is already in use!" });
    }

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Save new user
    const newUser = new User({ username, email: email.toLowerCase(), password: hashedPassword });
    await newUser.save();

    res.status(201).send({ message: "User registered successfully!" });
  } catch (error) {
    res.status(500).send({ message: "Error registering user", error: error.message });
  }
});

// Login Route
app.post("/api/auth/signin", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).send({ message: "Email and password are required!" });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(401).send({ message: "Invalid email or password" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).send({ message: "Invalid email or password" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.status(200).send({ message: "Login successful", token, username: user.username });
  } catch (error) {
    res.status(500).send({ message: "Error logging in", error: error.message });
  }
});

// Protected Route
app.get("/protected", verifyToken, (req, res) => {
  res.status(200).send({ message: "This is a protected route!" });
});

// Start Server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
