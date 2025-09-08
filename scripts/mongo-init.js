// MongoDB initialization script for Docker
db = db.getSiblingDB('media-library');

// Create application user with read/write permissions
db.createUser({
  user: 'api-user',
  pwd: 'api-password-123',
  roles: [
    {
      role: 'readWrite',
      db: 'media-library'
    }
  ]
});

// Create indexes for better performance
db.users.createIndex({ email: 1 }, { unique: true });
db.users.createIndex({ tokenVersion: 1 });
db.users.createIndex({ createdAt: -1 });

db.media.createIndex({ ownerId: 1 });
db.media.createIndex({ allowedUserIds: 1 });
db.media.createIndex({ createdAt: -1 });
db.media.createIndex({ storedName: 1 }, { unique: true });
db.media.createIndex({ ownerId: 1, createdAt: -1 });

print('Database initialized successfully!');
