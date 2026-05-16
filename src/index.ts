import express from 'express';
import authRoutes from './routes/auth';
import profileRoutes from './routes/profile';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.use('/', authRoutes);
app.use('/', profileRoutes);

app.listen(PORT, () => {
  console.log(`服务器运行在 http://localhost:${PORT}`);
});
