import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

export interface EncryptedData {
  ciphertextBase64: string;
  ivBase64: string;
  tagBase64: string;
}

export class CryptoUtil {
  /**
   * AES-256-GCM encryption
   */
  static aesGcmEncrypt(plaintext: string, key: string): EncryptedData {
    const keyBuffer = Buffer.from(key, 'hex');
    const iv = randomBytes(12); // 96-bit IV for GCM
    const cipher = createCipheriv('aes-256-gcm', keyBuffer, iv);
    
    cipher.setAAD(Buffer.from('media-library-api', 'utf8'));
    
    let encrypted = cipher.update(plaintext, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    
    const tag = cipher.getAuthTag();
    
    return {
      ciphertextBase64: encrypted.toString('base64'),
      ivBase64: iv.toString('base64'),
      tagBase64: tag.toString('base64'),
    };
  }

  /**
   * AES-256-GCM decryption
   */
  static aesGcmDecrypt(
    ciphertextBase64: string,
    ivBase64: string,
    tagBase64: string,
    key: string,
  ): string {
    try {
      const keyBuffer = Buffer.from(key, 'hex');
      const iv = Buffer.from(ivBase64, 'base64');
      const ciphertext = Buffer.from(ciphertextBase64, 'base64');
      const tag = Buffer.from(tagBase64, 'base64');
      
      const decipher = createDecipheriv('aes-256-gcm', keyBuffer, iv);
      decipher.setAAD(Buffer.from('media-library-api', 'utf8'));
      decipher.setAuthTag(tag);
      
      let decrypted = decipher.update(ciphertext);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      
      return decrypted.toString('utf8');
    } catch (error) {
      throw new Error('Decryption failed');
    }
  }

  /**
   * Generate secure random bytes
   */
  static secureRandomBytes(length: number): Buffer {
    return randomBytes(length);
  }

  /**
   * Generate secure random string
   */
  static secureRandomString(length: number): string {
    return randomBytes(length).toString('hex');
  }
}
