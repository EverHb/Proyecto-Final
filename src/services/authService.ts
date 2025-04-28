import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User, { IUser } from '../models/userModel';

class AuthService {
    async hashPassword(password: string): Promise<string> {
        const saltRounds = 10;
        return await bcrypt.hash(password, saltRounds);
    }

    async validatePassword(password: string, hashedPassword: string): Promise<boolean> {
        return await bcrypt.compare(password, hashedPassword);
    }

    generateToken(userId: string, role: string): string {
        const payload = { id: userId, role: role };
        const secret = process.env.JWT_SECRET || 'your_jwt_secret';
        const options = { expiresIn: '1h' };
        return jwt.sign(payload, secret, options);
    }

    async registerUser(username: string, password: string, role: string) {
        const hashedPassword = await this.hashPassword(password);
        const newUser = new User({ username, password: hashedPassword, role });
        return await newUser.save();
    }

    async loginUser(username: string, password: string) {
        const user = await User.findOne({ username }) as IUser;
        if (user && await this.validatePassword(password, user.password)) {
            const token = this.generateToken(user._id.toString(), user.role as string); // Usa .toString()
            return { token, user };
        }
        throw new Error('Invalid credentials');
    }
}

export default new AuthService();