import mongoose, { Document, Schema } from 'mongoose';

export interface IUser extends Document {
    _id: mongoose.Types.ObjectId; // Asegúrate de incluir esto
    username: string;
    password: string;
    role: 'Admin' | 'Editor' | 'Viewer';
    activityHistory: string[];
}

const userSchema: Schema<IUser> = new Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ['Admin', 'Editor', 'Viewer'],
        default: 'Viewer'
    },
    activityHistory: {
        type: [String],
        default: []
    }
}, {
    timestamps: true
});

const User = mongoose.model<IUser>('User', userSchema);

export default User;