import express from 'express';
import dotenv from 'dotenv';
import authRoutes from './routes/auth.js';
import path from 'path';
import cors from 'cors';

dotenv.config();
const app = express();

app.use(express.json());

app.use('/api/auth', authRoutes);
app.use('/uploads', express.static(path.join(process.cwd(), 'uploads')));

const PORT = process.env.PORT || 3000;

app.get("/", (req, res) => {
  res.send("Response traffic Success!");
});

app.use(cors({
  origin : '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

const startServer = async () => {

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server is running on port ${PORT}`);
  });
};

startServer();
