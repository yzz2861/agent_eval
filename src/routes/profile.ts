import { Router, Response } from 'express';
import { authMiddleware, AuthRequest } from '../middleware/auth';

const router = Router();

router.get('/profile', authMiddleware, (req: AuthRequest, res: Response): void => {
  if (!req.user) {
    res.status(401).json({ message: '未授权' });
    return;
  }

  res.json({
    username: req.user.username,
    role: req.user.role
  });
});

export default router;
