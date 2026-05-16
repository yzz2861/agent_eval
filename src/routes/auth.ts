import { Router, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const router = Router();
const JWT_SECRET = process.env.JWT_SECRET || 'my-secret-key';

const MOCK_ADMIN = {
  username: 'admin',
  passwordHash: bcrypt.hashSync('123456', 10),
  role: 'superuser'
};

interface LoginRequest {
  username: string;
  password: string;
}

router.post('/login', (req: Request<{}, {}, LoginRequest>, res: Response): void => {
  const { username, password } = req.body;

  if (!username || !password) {
    res.status(400).json({ message: '用户名和密码不能为空' });
    return;
  }

  if (username !== MOCK_ADMIN.username) {
    res.status(401).json({ message: '用户名或密码错误' });
    return;
  }

  const isPasswordValid = bcrypt.compareSync(password, MOCK_ADMIN.passwordHash);
  if (!isPasswordValid) {
    res.status(401).json({ message: '用户名或密码错误' });
    return;
  }

  const token = jwt.sign(
    { username: MOCK_ADMIN.username, role: MOCK_ADMIN.role },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  res.json({ token });
});

export default router;
