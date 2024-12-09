import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import db from "../config/db.js";
import nodemailer from "nodemailer";
import crypto from "crypto";
import { nanoid } from "nanoid";

const router = express.Router();

const unverifiedUsers = new Map();
const id = nanoid();

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
      data : {
        email
      }
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

    if (
      userData.otp !== parseInt(otp) ||
      Date.now() > userData.otpExpires
    ) {
      return res
        .status(400)
        .json({ message: "Kode OTP salah atau telah kadaluarsa." });
    }
    
    unverifiedUsers.delete(email);

    await db`
      INSERT INTO users (id, name, email, password, isVerified)
      VALUES ( ${userData.id},${userData.name}, ${userData.email}, ${userData.password}, ${true})
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
  const { email, password } = req.body;

  try {
    const user = await db`
      SELECT * FROM users WHERE email = ${email}
    `;

    if (user.length === 0) {
      return res.status(404).json({ message: "Email tidak ditemukan" });
    }

    const currentUser = user[0];

    const isMatch = await bcrypt.compare(password, currentUser.password);

    if (!isMatch) {
      return res.status(400).json({ message: "Password salah" });
    }

    const token = jwt.sign({ id: currentUser.id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({ message: "Login Berhasil", token });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Login Gagal", error: error.message });
  }
});

router.get("/users", async (req, res) => {
  try {
    const users = await db`
      SELECT id, name, email, isVerified FROM users
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

export default router;
