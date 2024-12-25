  import express from "express";
  import bcrypt from "bcrypt";
  import jwt from "jsonwebtoken";
  import db from "../config/db.js";
  import nodemailer from "nodemailer";
  import crypto from "crypto";
  import multer from "multer";
  import authenticateToken from "../middleware/authMiddleware.js";
  import { nanoid } from "nanoid";
  import { Storage } from '@google-cloud/storage'; 
  import dotenv from "dotenv";

  dotenv.config();

  const router = express.Router();

  const unverifiedUsers = new Map();
  const id = nanoid();

  const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 }, 
  });

  const googleCredentials = JSON.parse(
    process.env.GOOGLE_APPLICATION_CREDENTIALS
  );

  const storage = new Storage({
    credentials: googleCredentials,
  });

  const bucketName = 'mama-care-bucket';

  const uploadFileToGCS = async (file) => {
    const uniqueFileName = `${Date.now()}-${nanoid()}-${file.originalname}`;
    const blob = storage.bucket(bucketName).file(uniqueFileName);
    const blobStream = blob.createWriteStream({
      resumable: false,
      contentType: file.mimetype,
    });

    return new Promise((resolve, reject) => {
      blobStream.on('error', (err) => reject(err));
      blobStream.on('finish', () => {
        // Mengembalikan URL file yang diupload
        resolve(`https://storage.googleapis.com/${bucketName}/${uniqueFileName}`);
      });
      blobStream.end(file.buffer);
    });
  };

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  router.post("/register", async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "Semua field harus diisi" });
    }

    try {
      if (unverifiedUsers.has(email)) {
        return res
          .status(409)
          .json({ message: "Akun dengan email ini sedang menunggu verifikasi." });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      const otp = crypto.randomInt(100000, 999999); // Kode OTP 6 digit
      const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

      unverifiedUsers.set(email, {
        id,
        name,
        email,
        password: hashedPassword,
        otp,
        otpExpires,
      });

      const htmlContent = `
        <div style="font-family: Arial, sans-serif; color: #333;">
          <div style="background-color: #f7f7f7; padding: 20px; text-align: center;">
            <img src="https://res.cloudinary.com/dtonikyjm/image/upload/v1732804728/chatter-logo-panjang.jpg" alt="Chatter Logo" style="width: auto; height: 100px;">
          </div>
          <div style="padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-top: 10px;">
            <p>Hi ${name},</p>
            <p>Tinggal selangkah lagi untuk menyelesaikan proses, mohon konfirmasi dengan memasukkan kode OTP di bawah ini.</p>
            <div style="text-align: center; font-size: 24px; font-weight: bold; padding: 20px; background-color: #f1f1f1; border-radius: 5px;">
              ${otp}
            </div>
            <p style="color: #666;">Kode ini hanya berlaku selama 10 menit. Jangan pernah membagikan kode OTP kepada siapa pun!</p>
            <p>Jika ada pertanyaan atau membutuhkan bantuan, silakan hubungi call center kami di +62 821-1723-6590 atau melalui email di <a href="chatter0810@gmail.com" style="color: #1a73e8;">chatter@co.id</a>.</p>
          </div>
        </div>
      `;

      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Kode OTP Verifikasi Email",
        html: htmlContent,
      };

      await transporter.sendMail(mailOptions);

      res.status(201).json({
        message: "OTP sent successfully. Please check your email.",
        data: {
          email,
        },
      });
    } catch (error) {
      console.error("Register error:", error);
      res.status(500).json({
        message: "Register Gagal",
        error: error.message,
      });
    }
  });

  router.post("/verify-otp", async (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ message: "Email dan OTP diperlukan." });
    }

    try {
      const userData = unverifiedUsers.get(email);

      if (!userData) {
        return res
          .status(404)
          .json({ message: "Email tidak ditemukan dalam data pending." });
      }

      if (userData.otp !== parseInt(otp) || Date.now() > userData.otpExpires) {
        return res
          .status(400)
          .json({ message: "Kode OTP salah atau telah kadaluarsa." });
      }

      unverifiedUsers.delete(email);

      await db`
        INSERT INTO users (id, name, email, password, isVerified)
        VALUES ( ${userData.id},${userData.name}, ${userData.email}, ${
        userData.password
      }, ${true})
      `;

      res.status(200).json({ message: "Email berhasil diverifikasi." });
    } catch (error) {
      console.error("Verify OTP error:", error);
      res
        .status(500)
        .json({ message: "Verifikasi OTP Gagal", error: error.message });
    }
  });

  router.post("/login", async (req, res) => {
    const { email, password } = req.body; // Removed name and profile_picture from here

    try {
      const user = await db`
        SELECT * FROM users WHERE email = ${email}
      `;

      if (user.length === 0) {
        return res
          .status(404)
          .json({ 
            message: "Email atau password tidak ditemukan",    
          });
      }

      const currentUser = user[0];

      const isMatch = await bcrypt.compare(password, currentUser.password);

      if (!isMatch) {
        return res.status(400).json({ message: "Password salah" });
      }

      const token = jwt.sign({ id: currentUser.id }, process.env.JWT_SECRET, {
        expiresIn: "1h",
      });

      // Return the user data including profile_picture
      res.json(
        { 
          message: "Login Berhasil",
          data : {
            id: currentUser.id, 
            name: currentUser.name, 
            email: currentUser.email, 
            profile_picture: currentUser.profile_picture, 
            header_picture: currentUser.header_picture,
            created_at: currentUser.created_at
          },
          token 
        });
        console.log("User data:", currentUser);
    } catch (error) {
      console.error("Login error:", error);
      res.status(500).json({ message: "Login Gagal", error: error.message });
    }
  });

  router.get("/users", async (req, res) => {
    try {
      const users = await db`
        SELECT id, name, email, isVerified, profile_picture FROM users
      `;

      if (users.length === 0) {
        return res
          .status(404)
          .json({ message: "Tidak ada pengguna yang ditemukan." });
      }

      res.status(200).json({
        message: "Berhasil mengambil data pengguna.",
        users,
      });
    } catch (error) {
      console.error("Error saat mengambil data pengguna:", error);
      res.status(500).json({
        message: "Gagal mengambil data pengguna.",
        error: error.message,
      });
    }
  });

  router.put('/edit-profile', authenticateToken, upload.fields([{ name: 'profile_picture' }, { name: 'header_picture' }]), async (req, res) => {
    try {
      const { id } = req.user;
      const { name, password} = req.body;
      const profilePictureFile = req.files['profile_picture'] ? req.files['profile_picture'][0] : null;
      const headerPictureFile = req.files['header_picture'] ? req.files['header_picture'][0] : null;

      // Ambil ID pengguna dari token
      const userId = req.user.id;

      // Jika id baru diberikan, periksa apakah sudah ada yang menggunakannya
      if (id) {
        const existingUser = await db`
          SELECT * FROM users WHERE id = ${id} AND id != ${userId}
        `;
        if (existingUser.length > 0) {
          return res.status(400).json({ error: 'ID sudah digunakan oleh pengguna lain.' });
        }
      }

      // Siapkan field dan nilai yang akan diperbarui
      const updateFields = [];
      const updateValues = [];

      if (name) {
        updateFields.push(`name = $${updateFields.length + 1}`);
        updateValues.push(name);
      }

      if (password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        updateFields.push(`password = $${updateFields.length + 1}`);
        updateValues.push(hashedPassword);
      }

      // Upload ke Google Cloud Storage jika ada file
      if (profilePictureFile) {
        const profilePictureUrl = await uploadFileToGCS(profilePictureFile);
        updateFields.push(`profile_picture = $${updateFields.length + 1}`);
        updateValues.push(profilePictureUrl);
      }

      if (headerPictureFile) {
        const headerPictureUrl = await uploadFileToGCS(headerPictureFile);
        updateFields.push(`header_picture = $${updateFields.length + 1}`);
        updateValues.push(headerPictureUrl);
      }

      if (id) {
        updateFields.push(`id = $${updateFields.length + 1}`);
        updateValues.push(id);
      }

      // Jika tidak ada field yang di-update, kembalikan respons
      if (updateFields.length === 0) {
        return res.status(400).json({ error: 'No fields to update' });
      }

      // Tambahkan userId untuk WHERE clause
      updateValues.push(userId);

      // Buat query SQL
      const query = `
        UPDATE users
        SET ${updateFields.join(', ')}
        WHERE id = $${updateValues.length}
      `;

      // Eksekusi query
      await db(query, updateValues);

      // Response sukses
      res.status(200).json({ message: 'Profile updated successfully' });
    } catch (error) {
      console.error('Error updating profile:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });

  router.post("/create-post", authenticateToken, upload.single('media'), async (req, res) => {
    const { content } = req.body;
    const userId = req.user.id;
    const mediaFile = req.file;

    // Validasi input
    if (!content && !mediaFile) {
      return res.status(400).json({ message: "Content or media file is required." });
    }

    try {
      let mediaUrl = null;

      // Upload media file jika ada
      if (mediaFile) {
        const allowedMimeTypes = ['image/jpeg', 'image/png', 'video/mp4', 'video/webm', 'image/gif'];
        if (!allowedMimeTypes.includes(mediaFile.mimetype)) {
          return res.status(400).json({ message: "Unsupported file type." });
        }
        mediaUrl = await uploadFileToGCS(mediaFile);
      }

      const post = await db`
        INSERT INTO posts (user_id, content, media_url)
        VALUES (${userId}, ${content}, ${mediaUrl})
        RETURNING *
      `;

      res.status(201).json({ message: "Post created successfully", data: post[0] });
    } catch (error) {
      console.error("Error creating post:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  });

  router.post("/create-comment", authenticateToken, async (req, res) => {
    const { post_id, content } = req.body;
    const userId = req.user.id;

    // Validasi input
    if (!post_id || !content) {
      return res.status(400).json({ message: "Post ID and content are required." });
    }

    try {
      const comment = await db`
        INSERT INTO comments (post_id, user_id, content)
        VALUES (${post_id}, ${userId}, ${content})
        RETURNING *
      `;

      res.status(201).json({ message: "Comment created successfully", data: comment[0] });
    } catch (error) {
      console.error("Error creating comment:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  });

  router.get("/posts", async (req, res) => {
    const { page = 1, limit = 20 } = req.query; // Default pagination
    const offset = (page - 1) * limit;

    try {
      const posts = await db`
        SELECT p.id, p.content, p.media_url, p.created_at, u.name AS user_name, u.profile_picture, u.id AS user_id
        FROM posts p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;

      res.status(200).json({ message: "Posts fetched successfully", data: posts });
    } catch (error) {
      console.error("Error fetching posts:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  });


  export default router;
