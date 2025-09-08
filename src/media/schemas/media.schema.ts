import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';
import { User } from '../../users/schemas/user.schema';

export type MediaDocument = Media & Document;

@Schema({
  timestamps: true,
  collection: 'media',
  toJSON: {
    transform: function(doc, ret: any) {
      ret.id = ret._id;
      delete ret._id;
      delete ret.__v;
      return ret;
    },
  },
})
export class Media {
  @Prop({ type: Types.ObjectId, ref: 'User', required: true, index: true })
  ownerId!: Types.ObjectId;

  @Prop({ required: true })
  fileName!: string;

  @Prop({ required: true, unique: true })
  storedName!: string;

  @Prop({ required: true })
  filePath!: string;

  @Prop({
    required: true,
    enum: ['image/jpeg'],
    default: 'image/jpeg',
  })
  mimeType!: 'image/jpeg';

  @Prop({ required: true, min: 1 })
  size!: number;

  @Prop({ type: [{ type: Types.ObjectId, ref: 'User' }], default: [] })
  allowedUserIds!: Types.ObjectId[];

  createdAt!: Date;
  updatedAt!: Date;
}

export const MediaSchema = SchemaFactory.createForClass(Media);

// Indexes for performance
MediaSchema.index({ ownerId: 1 });
MediaSchema.index({ allowedUserIds: 1 });
MediaSchema.index({ createdAt: -1 });
MediaSchema.index({ storedName: 1 }, { unique: true });
MediaSchema.index({ 'ownerId': 1, 'createdAt': -1 });
