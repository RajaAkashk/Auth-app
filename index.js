const { initializeDatabase } = require("./db/db.connect");
const User = require("./models/user.model");
const bcrypt = require("bcrypt");
const express = require("express");
const app = express();
const cors = require("cors");
const jwt = require("jsonwebtoken");

// Initialize database
initializeDatabase();

app.use(express.json());
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

const authenticateJWT = (req, res, next) => {
  const token = req.headers["authorization"];

  if (!token) return res.status(401).json({ message: "Access denied" });
  const tokenWithoutBearer = token.split(" ")[1];
  try {
    const decodedToken = jwt.verify(tokenWithoutBearer, process.env.JWT_SECRET);
    req.user = decodedToken;
    next();
  } catch {
    res.status(403).json({ message: "Invalid token" });
  }
};

const authorizeRole = (roles) => (req, res, next) => {
  if (!roles.includes(req.user.role))
    return res.status(403).send("Access forbidden user's role not found.");
  next();
};

app.post("/register", async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) {
    return res.status(400).json({
      message: "All fields (username, password, and role) are required.",
    });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword, role });
    await newUser.save();
    res.status(201).json({ message: "User registered", user: newUser });
  } catch {
    res.status(500).json({ message: "Registration failed." });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required" });
  }
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).send("User not found");

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(403).send("Invalid password");

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.json({ token });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ message: "Login failed. Please try again later." });
  }
});

app.get(
  "/admin",
  authenticateJWT,
  authorizeRole(["admin"]),
  async (req, res) => {
    try {
      res.json({ message: "Welcome Admin!!" });
    } catch (error) {
      console.error("Error in /Admin route:", error);
      res.status(500).json({
        message: "Something went wrong with admin route, please try again.",
      });
    }
  }
);

app.get("/teacher", authenticateJWT, authorizeRole(["teacher"]), (req, res) => {
  try {
    res.json({ message: "Welcome Teacher" });
  } catch (error) {
    console.error("Error in /teacher route:", error);
    res.status(500).json({
      message: "Something went wrong with teacher route, please try again.",
    });
  }
});

app.get("/student", authenticateJWT, authorizeRole(["student"]), (req, res) => {
  try {
    res.json({ message: "Welcome Student" });
  } catch (error) {
    console.error("Error in /student route:", error);
    res.status(500).json({
      message: "Something went wrong with student route, please try again.",
    });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server is running on PORT:", PORT);
});
