const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const fs = require("fs");
const path = require("path");

const app = express();

// ------------------ Config ------------------
cloudinary.config({
  cloud_name: "domehot9s",  // replace with your Cloudinary details
  api_key: "295212599248667",
  api_secret: "pUBCpuC__UsErst0DW0eI1zvMaM"
});

const JWT_SECRET = "SONARA_GLOBAL_SECRET_2026";

// Multer for uploads
const upload = multer({ dest: "uploads/" });

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve frontend files
app.use(express.static("public"));  // <-- serves index.html, about.html, etc.

// Default route to index.html
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ------------------ MongoDB ------------------
mongoose.connect("mongodb+srv://samuel:samuel2026@cluster0.n9vhak3.mongodb.net/?appName=Cluster0", {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log("MongoDB connected"))
  .catch(err => console.log(err));

// ------------------ Schemas ------------------
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  bio: { type: String, default: "" },
  avatar: { type: String, default: "" },
  verified: { type: Boolean, default: false }
});

const songSchema = new mongoose.Schema({
  title: String,
  artist: String,
  premium: Boolean,
  audioUrl: String,
  imageUrl: String,      // cover image
  uploader: String,
  uploaderAvatar: String,
  uploaderVerified: Boolean,
  likes: { type: Number, default: 0 },
  views: { type: Number, default: 0 },
  comments: [{ user: String, text: String }]
});

const User = mongoose.model("User", userSchema);
const Song = mongoose.model("Song", songSchema);

// ------------------ Auth Middleware ------------------
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ message: "Unauthorized" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

// ------------------ Auth Routes ------------------
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashed });
  await user.save();
  res.json({ message: "Registered" });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.json({ message: "User not found" });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.json({ message: "Wrong password" });
  const token = jwt.sign({ username }, JWT_SECRET);
  res.json({ token });
});

// ------------------ Profile Route ------------------
app.get("/api/profile/:username", async (req, res) => {
  const user = await User.findOne({ username: req.params.username });
  if (!user) return res.status(404).json({ message: "User not found" });
  const songs = await Song.find({ uploader: user.username });
  res.json({ user, songs });
});

// ------------------ Upload Song with Cover ------------------
app.post("/api/upload", authMiddleware, upload.fields([
  { name: "audio", maxCount: 1 },
  { name: "cover", maxCount: 1 }   // song cover
]), async (req, res) => {
  try {
    const { title, artist, premium } = req.body;
    const audioFile = req.files.audio[0];
    const coverFile = req.files.cover ? req.files.cover[0] : null;

    // Upload audio to Cloudinary
    const audioResult = await cloudinary.uploader.upload(audioFile.path, {
      resource_type: "video",
      folder: "songs"
    });

    let coverUrl = "";
    if (coverFile) {
      const coverResult = await cloudinary.uploader.upload(coverFile.path, {
        folder: "song_covers"
      });
      coverUrl = coverResult.secure_url;
    }

    const user = await User.findOne({ username: req.user.username });

    const song = new Song({
      title,
      artist,
      premium: premium === "true",
      audioUrl: audioResult.secure_url,
      imageUrl: coverUrl,
      uploader: user.username,
      uploaderAvatar: user.avatar,
      uploaderVerified: user.verified
    });

    await song.save();

    // Delete temp files
    fs.unlinkSync(audioFile.path);
    if (coverFile) fs.unlinkSync(coverFile.path);

    res.json({ message: "Song uploaded successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Upload failed" });
  }
});

// ------------------ Get All Songs ------------------
app.get("/api/songs", async (req, res) => {
  const songs = await Song.find();
  res.json(songs);
});

// ------------------ Delete Song ------------------
app.delete("/api/delete/:id", authMiddleware, async (req, res) => {
  const song = await Song.findById(req.params.id);
  if (!song) return res.status(404).json({ message: "Not found" });
  if (song.uploader !== req.user.username) return res.status(403).json({ message: "Forbidden" });
  await Song.deleteOne({ _id: req.params.id });
  res.json({ message: "Deleted" });
});

// ------------------ Start Server ------------------
const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
