const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;

// -------------------- Config --------------------
// Cloudinary config
cloudinary.config({
  cloud_name: "domehot9s",
  api_key: "295212599248667",
  api_secret: "pUBCpuC__UsErst0DW0eI1zvMaM"
});

// JWT secret
const JWT_SECRET = "SONARA_GLOBAL_SECRET_2026";

// Multer for uploads
const upload = multer({ dest: "uploads/" });

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// -------------------- MongoDB --------------------
mongoose.connect("mongodb+srv://samuel:samuel2026@cluster0.n9vhak3.mongodb.net/?appName=Cluster0", {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(()=>console.log("MongoDB connected"))
  .catch(err=>console.log(err));

// -------------------- Schemas --------------------
const userSchema = new mongoose.Schema({
  username:String,
  password:String,
  bio:{type:String,default:""},
  avatar:{type:String,default:""},
  verified:{type:Boolean,default:false},
  followers:{type:[String],default:[]},
  following:{type:[String],default:[]}
});

const songSchema = new mongoose.Schema({
  title:String,
  artist:String,
  premium:Boolean,
  audioUrl:String,
  imageUrl:String,
  uploader:String,
  uploaderAvatar:String,
  uploaderVerified:Boolean,
  likes:{type:Number,default:0},
  views:{type:Number,default:0},
  comments:[{user:String,text:String}],
  featured:{type:Boolean,default:false}
});

const playlistSchema = new mongoose.Schema({
  name:String,
  owner:String,
  songs:[String],
  shared:Boolean
});

const User = mongoose.model("User",userSchema);
const Song = mongoose.model("Song",songSchema);
const Playlist = mongoose.model("Playlist",playlistSchema);

// -------------------- Middleware --------------------
const authMiddleware = (req,res,next)=>{
  const token = req.headers.authorization;
  if(!token) return res.status(401).json({message:"Unauthorized"});
  try{
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  }catch(err){
    return res.status(401).json({message:"Invalid token"});
  }
};

// -------------------- Auth --------------------
app.post("/api/register", async (req,res)=>{
  const {username,password} = req.body;
  const hashed = await bcrypt.hash(password,10);
  const user = new User({username,password:hashed});
  await user.save();
  res.json({message:"Registered"});
});

app.post("/api/login", async (req,res)=>{
  const {username,password} = req.body;
  const user = await User.findOne({username});
  if(!user) return res.json({message:"User not found"});
  const match = await bcrypt.compare(password,user.password);
  if(!match) return res.json({message:"Wrong password"});
  const token = jwt.sign({username}, JWT_SECRET);
  res.json({token});
});

// -------------------- Profile --------------------
app.get("/api/profile/:username", async (req,res)=>{
  const user = await User.findOne({username:req.params.username});
  if(!user) return res.status(404).json({message:"User not found"});
  const songs = await Song.find({uploader:user.username});
  res.json({user,songs});
});

app.put("/api/profile/update", authMiddleware, upload.single("avatar"), async (req,res)=>{
  try{
    const user = await User.findOne({username:req.user.username});
    if(req.body.username) user.username=req.body.username;
    if(req.body.bio) user.bio=req.body.bio;
    if(req.file){
      const result = await cloudinary.uploader.upload(req.file.path,{folder:"avatars"});
      user.avatar=result.secure_url;
    }
    await user.save();
    res.json({message:"Profile updated"});
  }catch(err){res.status(500).json({message:"Server error"});}
});

// -------------------- Upload Song --------------------
const multer = require("multer");
const upload = multer({ dest: "uploads/" }); // temp storage before Cloudinary

app.post("/api/upload", authMiddleware, upload.fields([
  { name: "audio", maxCount: 1 },
  { name: "cover", maxCount: 1 } // <-- new field for song cover
]), async (req, res) => {
  try {
    const { title, artist, premium } = req.body;
    const audioFile = req.files.audio[0];
    const coverFile = req.files.cover ? req.files.cover[0] : null;

    // Upload audio to Cloudinary
    const audioResult = await cloudinary.uploader.upload(audioFile.path, {
      resource_type: "video", folder: "songs"
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
      imageUrl: coverUrl, // save cover URL
      uploader: user.username,
      uploaderAvatar: user.avatar,
      uploaderVerified: user.verified
    });

    await song.save();
    res.json({ message: "Song uploaded successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Upload failed" });
  }
});


// -------------------- Get Songs --------------------
app.get("/api/songs", async (req,res)=>{
  const songs = await Song.find();
  res.json(songs);
});

// -------------------- Featured --------------------
app.get("/api/featured", async (req,res)=>{
  const songs = await Song.find({featured:true});
  res.json(songs);
});

// -------------------- Likes, Views, Comments --------------------
app.post("/api/like/:id", async (req,res)=>{
  const song = await Song.findById(req.params.id);
  if(song){song.likes++; await song.save();}
  res.json({message:"Liked"});
});

app.post("/api/view/:id", async (req,res)=>{
  const song = await Song.findById(req.params.id);
  if(song){song.views++; await song.save();}
  res.json({message:"Viewed"});
});

app.post("/api/comment/:id", authMiddleware, async (req,res)=>{
  const song = await Song.findById(req.params.id);
  if(song){song.comments.push({user:req.user.username,text:req.body.text}); await song.save();}
  res.json({message:"Comment added"});
});

// -------------------- Delete Song --------------------
app.delete("/api/delete/:id", authMiddleware, async (req,res)=>{
  const song = await Song.findById(req.params.id);
  if(!song) return res.status(404).json({message:"Not found"});
  if(song.uploader!==req.user.username && req.user.username!=="admin") return res.status(403).json({message:"Forbidden"});
  await Song.deleteOne({_id:req.params.id});
  res.json({message:"Deleted"});
});

// -------------------- Admin --------------------
app.post("/api/admin/verify/:username", authMiddleware, async (req,res)=>{
  if(req.user.username!=="admin") return res.status(403).json({message:"Forbidden"});
  const user = await User.findOne({username:req.params.username});
  if(user){user.verified=true; await user.save(); res.json({message:"Verified"});}
  else res.status(404).json({message:"User not found"});
});

app.post("/api/admin/feature/:id", authMiddleware, async (req,res)=>{
  if(req.user.username!=="admin") return res.status(403).json({message:"Forbidden"});
  const song = await Song.findById(req.params.id);
  if(song){song.featured=true; await song.save(); res.json({message:"Featured"});}
  else res.status(404).json({message:"Song not found"});
});

app.delete("/api/admin/delete/:id", authMiddleware, async (req,res)=>{
  if(req.user.username!=="admin") return res.status(403).json({message:"Forbidden"});
  await Song.deleteOne({_id:req.params.id});
  res.json({message:"Deleted"});
});

// -------------------- Search --------------------
app.get("/api/search/:q", async (req,res)=>{
  const q=req.params.q;
  const songs = await Song.find({title:{$regex:q,$options:"i"}});
  res.json(songs);
});

// -------------------- Playlists --------------------
app.post("/api/playlists", authMiddleware, async (req,res)=>{
  const {name} = req.body;
  const playlist = new Playlist({name,owner:req.user.username,songs:[],shared:false});
  await playlist.save();
  res.json({message:"Playlist created"});
});

app.get("/api/playlists/:username", async (req,res)=>{
  const pls = await Playlist.find({owner:req.params.username});
  res.json(pls);
});

app.post("/api/playlist/:id/share", authMiddleware, async (req,res)=>{
  const pl = await Playlist.findById(req.params.id);
  if(pl){pl.shared=true; await pl.save(); res.json({message:"Shared"});}
  else res.status(404).json({message:"Playlist not found"});
});// Follow a user
app.post("/api/follow/:username", authMiddleware, async (req,res)=>{
  try {
    const target = await User.findOne({username:req.params.username});
    const me = await User.findOne({username:req.user.username});
    if(!target) return res.status(404).json({message:"User not found"});
    if(target.username === me.username) return res.status(400).json({message:"Cannot follow yourself"});
    
    if(!target.followers.includes(me.username)){
      target.followers.push(me.username);
      me.following.push(target.username);
      await target.save();
      await me.save();
      return res.json({message:`You are now following ${target.username}`});
    } else {
      return res.json({message:"Already following"});
    }
  } catch(err){res.status(500).json({message:"Server error"});}
});

// Unfollow a user
app.post("/api/unfollow/:username", authMiddleware, async (req,res)=>{
  try {
    const target = await User.findOne({username:req.params.username});
    const me = await User.findOne({username:req.user.username});
    if(!target) return res.status(404).json({message:"User not found"});
    if(target.username === me.username) return res.status(400).json({message:"Cannot unfollow yourself"});
    
    target.followers = target.followers.filter(u=>u!==me.username);
    me.following = me.following.filter(u=>u!==target.username);
    await target.save();
    await me.save();
    return res.json({message:`You unfollowed ${target.username}`});
  } catch(err){res.status(500).json({message:"Server error"});}
});



// -------------------- Start Server --------------------
const PORT = 5000;
app.listen(PORT, ()=>console.log(`Server running on port ${PORT}`));
