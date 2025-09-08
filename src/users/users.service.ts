import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as argon2 from 'argon2';
import { User, UserDocument } from './schemas/user.schema';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
  ) {}

  async create(email: string, password: string, role: 'user' | 'admin' = 'user'): Promise<UserDocument> {
    const existingUser = await this.userModel.findOne({ email }).exec();
    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    const passwordHash = await argon2.hash(password);
    
    const user = new this.userModel({
      email,
      passwordHash,
      role,
    });

    return user.save();
  }

  async findById(id: string): Promise<UserDocument | null> {
    return this.userModel.findById(id).exec();
  }

  async findByEmail(email: string): Promise<UserDocument | null> {
    return this.userModel.findOne({ email }).exec();
  }

  async validatePassword(user: UserDocument, password: string): Promise<boolean> {
    console.log('user', user);
    console.log('password', password);
    try {
      return await argon2.verify(user.passwordHash, password);
    } catch {
      return false;
    }
  }

  async findAll(): Promise<UserDocument[]> {
    return this.userModel.find().exec();
  }

  async updateRefreshToken(
    userId: string,
    refreshData: {
      rt_hash: string | null;
      rt_ciphertext: string | null;
      rt_iv: string | null;
      rt_tag: string | null;
      deviceInfo?: {
        userAgent: string | null;
        ip: string | null;
        createdAt: Date | null;
        expiresAt: Date | null;
      };
    },
  ): Promise<void> {
    await this.userModel
      .findByIdAndUpdate(userId, { refresh: refreshData })
      .exec();
  }

  async incrementTokenVersion(userId: string): Promise<void> {
    await this.userModel
      .findByIdAndUpdate(userId, { $inc: { tokenVersion: 1 } })
      .exec();
  }

  async clearRefreshToken(userId: string): Promise<void> {
    await this.userModel
      .findByIdAndUpdate(userId, {
        refresh: {
          rt_hash: null,
          rt_ciphertext: null,
          rt_iv: null,
          rt_tag: null,
          deviceInfo: {
            userAgent: null,
            ip: null,
            createdAt: null,
            expiresAt: null,
          },
        },
      })
      .exec();
  }

  async getUserProfile(userId: string): Promise<UserDocument> {
    const user = await this.userModel.findById(userId).exec();
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  async updateUser(userId: string, updateData: Partial<Pick<User, 'email' | 'role'>>): Promise<UserDocument> {
    const user = await this.userModel
      .findByIdAndUpdate(userId, updateData, { new: true })
      .exec();
    
    if (!user) {
      throw new NotFoundException('User not found');
    }
    
    return user;
  }

  async deleteUser(userId: string): Promise<void> {
    const result = await this.userModel.findByIdAndDelete(userId).exec();
    if (!result) {
      throw new NotFoundException('User not found');
    }
  }

  async findUsers(skip = 0, limit = 10): Promise<{ users: UserDocument[]; total: number }> {
    const [users, total] = await Promise.all([
      this.userModel.find().skip(skip).limit(limit).exec(),
      this.userModel.countDocuments().exec(),
    ]);

    return { users, total };
  }
}
