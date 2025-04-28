import { Request, Response } from 'express';
import User from '../models/userModel';
import AuthService from '../services/authService';

class UserController {
    private authService: typeof AuthService;

    constructor() {
        this.authService = AuthService;
    }

    public async register(req: Request, res: Response): Promise<void> {
        try {
            const { username, password, role } = req.body;

            // Verifica si el usuario ya existe
            const existingUser = await User.findOne({ username });
            if (existingUser) {
                res.status(400).json({ message: 'El usuario ya existe' });
                return;
            }

            // Crea un nuevo usuario
            const newUser = new User({ username, password, role });
            await newUser.save();

            res.status(201).json({
                message: 'Usuario registrado exitosamente',
                user: {
                    username: newUser.username,
                    role: newUser.role,
                    activityHistory: newUser.activityHistory,
                    createdAt: newUser.createdAt,
                    updatedAt: newUser.updatedAt,
                    _id: newUser._id
                }
            });
        } catch (error) {
            res.status(500).json({ message: 'Error al registrar usuario', error });
        }
    }

    public async login(req: Request, res: Response): Promise<void> {
        try {
            const { username, password } = req.body;
            const user = await User.findOne({ username });
            if (!user || !(await this.authService.validatePassword(password, user.password))) {
                res.status(401).json({ message: 'Invalid credentials' });
                return;
            }
            const token = this.authService.generateToken(user._id.toString(), user.role as string); // Usa .toString()
            res.status(200).json({ token });
        } catch (error) {
            res.status(500).json({ message: 'Error logging in', error });
        }
    }

    public async updateProfile(req: Request, res: Response): Promise<void> {
        try {
            const { userId } = req.params;
            const updates = req.body;
            const updatedUser = await User.findByIdAndUpdate(userId, updates, { new: true });
            res.status(200).json(updatedUser);
        } catch (error) {
            res.status(500).json({ message: 'Error updating profile', error });
        }
    }

    public async getUserHistory(req: Request, res: Response): Promise<void> {
        try {
            const { userId } = req.params;
            const user = await User.findById(userId);
            if (!user) {
                res.status(404).json({ message: 'User not found' });
                return;
            }
            res.status(200).json(user.activityHistory);
        } catch (error) {
            res.status(500).json({ message: 'Error retrieving user history', error });
        }
    }

    public async getProfile(req: Request, res: Response): Promise<void> {
        try {
            const { id } = req.params;
            const user = await User.findById(id);
            if (!user) {
                res.status(404).json({ message: 'User not found' });
                return;
            }
            res.status(200).json(user);
        } catch (error) {
            res.status(500).json({ message: 'Error retrieving profile', error });
        }
    }

    public async deleteUser(req: Request, res: Response): Promise<void> {
        try {
            const { id } = req.params;
            const deletedUser = await User.findByIdAndDelete(id);
            if (!deletedUser) {
                res.status(404).json({ message: 'User not found' });
                return;
            }
            res.status(200).json({ message: 'User deleted successfully' });
        } catch (error) {
            res.status(500).json({ message: 'Error deleting user', error });
        }
    }

    public async getAllUsers(req: Request, res: Response): Promise<void> {
        try {
            const users = await User.find(); // Obtener todos los usuarios de la base de datos
            res.status(200).json(users);
        } catch (error) {
            res.status(500).json({ message: 'Error retrieving users', error });
        }
    }

    public async testConnection(req: Request, res: Response): Promise<void> {
        try {
            const users = await User.find();
            res.status(200).json(users);
        } catch (error) {
            res.status(500).json({ message: 'Error connecting to database', error });
        }
    }
}

export default UserController;