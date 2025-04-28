import express from 'express';
import UserController from '../controllers/userController';

const router = express.Router();
const userController = new UserController();

router.post('/register', userController.register);
router.post('/login', userController.login);
router.get('/profile/:id', userController.getProfile);
router.put('/profile/:id', userController.updateProfile);
router.get('/history/:id', userController.getUserHistory);
router.delete('/user/:id', userController.deleteUser);
router.get('/users', userController.getAllUsers);
router.get('/test', userController.testConnection);

export default router;