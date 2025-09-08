import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type UserDocument = User & Document;

@Schema({
  timestamps: true,
  collection: 'users',
  toJSON: {
    transform: function(doc, ret: any) {
      ret.id = ret._id;
      delete ret._id;
      delete ret.__v;
      delete ret.passwordHash;
      delete ret.refresh;
      return ret;
    },
  },
})
export class User {
  @Prop({
    required: true,
    unique: true,
    lowercase: true,
    index: true,
    match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email'],
  })
  email!: string;

  @Prop({ required: true })
  passwordHash!: string;

  @Prop({
    type: String,
    enum: ['user', 'admin'],
    default: 'user',
  })
  role!: 'user' | 'admin';

  @Prop({ type: Number, default: 0 })
  tokenVersion!: number;

  @Prop({
    type: {
      rt_hash: { type: String, default: null },
      rt_ciphertext: { type: String, default: null },
      rt_iv: { type: String, default: null },
      rt_tag: { type: String, default: null },
      deviceInfo: {
        userAgent: { type: String, default: null },
        ip: { type: String, default: null },
        createdAt: { type: Date, default: null },
        expiresAt: { type: Date, default: null },
      },
    },
    default: {
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
  refresh!: {
    rt_hash: string | null;
    rt_ciphertext: string | null;
    rt_iv: string | null;
    rt_tag: string | null;
    deviceInfo: {
      userAgent: string | null;
      ip: string | null;
      createdAt: Date | null;
      expiresAt: Date | null;
    };
  };

  createdAt!: Date;
  updatedAt!: Date;
}

export const UserSchema = SchemaFactory.createForClass(User);

// Indexes for performance
UserSchema.index({ email: 1 }, { unique: true });
UserSchema.index({ tokenVersion: 1 });
UserSchema.index({ createdAt: -1 });
