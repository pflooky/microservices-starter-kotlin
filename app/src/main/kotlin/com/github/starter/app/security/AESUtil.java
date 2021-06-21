package com.github.starter.app.security;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

/**
 * OpenSSL equivalent for AES encryption with and without PBKDF2 and key-obtention iteration (-iter)
 * <p>
 * References:
 * https://stackoverflow.com/a/41495143/90101
 * https://wiki.openssl.org/index.php/EVP_Key_Derivation
 * https://stackoverflow.com/a/63890651/90101
 */
public class AESUtil {
    private static final byte[] SALTED_MAGIC = "Salted__".getBytes();

    private final String pbeAlgorithm;
    private final String digestAlgorithm;
    private final int keyLengthInByte;


    private String encryptionPassword = "";
    private int keyObtentionIterations = 10000; // 10000 is openssl's default


    /**
     * @param pbeAlgorithm    - "AES/CBC/PKCS5Padding", "AES/ECB/PKCS5Padding"
     * @param digestAlgorithm - "SHA-256", "MD5"
     * @param keyLengthInBit  - 128, 256
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     */
    public AESUtil(String pbeAlgorithm, String digestAlgorithm, int keyLengthInBit) throws NoSuchAlgorithmException, NoSuchPaddingException {
        super();
        this.pbeAlgorithm = pbeAlgorithm;
        this.digestAlgorithm = digestAlgorithm;
        this.keyLengthInByte = keyLengthInBit / 8;
    }


    public String getEncryptionPassowrd() {
        return encryptionPassword;
    }

    public void setEncryptionPassowrd(String encryptionPassowrd) {
        this.encryptionPassword = encryptionPassowrd;
    }


    public int getKeyObtentionIterations() {
        return keyObtentionIterations;
    }

    public void setKeyObtentionIterations(int keyObtentionIterations) {
        this.keyObtentionIterations = keyObtentionIterations;
    }

    public String encryptString(String clearText, String password)
            throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException {
        return this.encryptString(clearText, password, false, -1);
    }

    public String encryptString(String clearText)
            throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException {
        return this.encryptString(clearText, this.encryptionPassword);
    }

    public String encryptStringWithPBKDF2(String clearText, String password, int hashIterations)
            throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException {
        return this.encryptString(clearText, password, true, hashIterations);
    }

    public void encryptFile(File inputFile, File outputFile, String password, boolean pbkdf2) throws Exception {
        final byte[] salt = (new SecureRandom()).generateSeed(8);
        byte[] keyAndIv = getKeyAndIv(password, pbkdf2, keyObtentionIterations, salt);
        final byte[] keyValue = Arrays.copyOfRange(keyAndIv, 0, this.keyLengthInByte);

        final SecretKeySpec key = new SecretKeySpec(keyValue, "AES");
        Cipher cipher = Cipher.getInstance(this.pbeAlgorithm);
        final byte[] iv = Arrays.copyOfRange(keyAndIv, this.keyLengthInByte, (this.keyLengthInByte + 16));
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        byte[] allBytes = array_concat(array_concat(SALTED_MAGIC, salt), cipher.doFinal(new FileInputStream(inputFile).readAllBytes()));
        new FileOutputStream(outputFile).write(allBytes);

//        try (FileOutputStream fileOut = new FileOutputStream(outputFile);
//             FileInputStream fileIn = new FileInputStream(inputFile);
//             CipherOutputStream cipherOut = new CipherOutputStream(fileOut, cipher)) {
////            fileOut.write(iv);
//            byte[] buffer = new byte[64];
//            int n = fileIn.read(buffer);
//            while (n != -1) {
//                cipherOut.write(buffer);
//                n = fileIn.read(buffer);
//            }
//        }
        System.out.println("Created encrypted file");
    }

    private String encryptString(String clearText, String password, boolean pbkdf2, int hashIterations)
            throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException {
        final byte[] salt = (new SecureRandom()).generateSeed(8);
        final byte[] inBytes = clearText.getBytes(StandardCharsets.UTF_8);

        byte[] keyAndIv = getKeyAndIv(password, pbkdf2, hashIterations, salt);

        // AES-256: 32 bytes key, 16 bytes iv
        // AES-128: 16 bytes key, 16 bytes iv
        final byte[] keyValue = Arrays.copyOfRange(keyAndIv, 0, this.keyLengthInByte);
        final SecretKeySpec key = new SecretKeySpec(keyValue, "AES");

        Cipher cipher = Cipher.getInstance(this.pbeAlgorithm);
        if (this.pbeAlgorithm.contains("ECB")) {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } else {
            // CBC
            final byte[] iv = Arrays.copyOfRange(keyAndIv, this.keyLengthInByte, (this.keyLengthInByte + 16));
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        }

        byte[] data = cipher.doFinal(inBytes);
        data = array_concat(array_concat(SALTED_MAGIC, salt), data);
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] getKeyAndIv(String password, boolean pbkdf2, int hashIterations, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (pbkdf2) {
            return deriveKeyAndIvWithPBKDF2(password, hashIterations, salt);
        } else {
            return deriveKeyAndIv(password.getBytes(StandardCharsets.ISO_8859_1), salt);
        }
    }

    public String encryptStringWithPBKDF2(String clearText)
            throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException {
        return this.encryptStringWithPBKDF2(clearText, encryptionPassword, keyObtentionIterations);
    }

    public String encryptStringWithPBKDF2(String clearText, String password)
            throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException {
        return this.encryptStringWithPBKDF2(clearText, password, keyObtentionIterations);
    }

    public String decrypt(String encryptedBase64, String password)
            throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException {
        return this.decrypt(encryptedBase64, password, false, -1);
    }

    public String decrypt(String encryptedBase64)
            throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException {
        return this.decrypt(encryptedBase64, this.encryptionPassword);
    }

    public String decryptWithPBKDF2(String encryptedBase64, String password, int hashIterations)
            throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException {

        return this.decrypt(encryptedBase64, password, true, hashIterations);
    }

    private String decrypt(String encryptedBase64, String password, boolean pbkdf2, int hashIterations)
            throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException {

        final byte[] inBytes = Base64.getDecoder().decode(encryptedBase64);

        final byte[] shouldBeMagic = Arrays.copyOfRange(inBytes, 0, SALTED_MAGIC.length);
        if (!Arrays.equals(shouldBeMagic, SALTED_MAGIC)) {
            throw new IllegalArgumentException("Bad magic number. Initial bytes from input do not match OpenSSL SALTED_MAGIC salt value.");
        }

        final byte[] salt = Arrays.copyOfRange(inBytes, SALTED_MAGIC.length, SALTED_MAGIC.length + 8);

        byte[] keyAndIv;
        if (pbkdf2) {
            keyAndIv = deriveKeyAndIvWithPBKDF2(password, hashIterations, salt);
        } else {
            keyAndIv = deriveKeyAndIv(password.getBytes(StandardCharsets.ISO_8859_1), salt);
        }

        final byte[] keyValue = Arrays.copyOfRange(keyAndIv, 0, this.keyLengthInByte);
        final SecretKeySpec key = new SecretKeySpec(keyValue, "AES");


        Cipher cipher = Cipher.getInstance(this.pbeAlgorithm);
        if (this.pbeAlgorithm.contains("ECB")) {
            cipher.init(Cipher.DECRYPT_MODE, key);
        } else {
            // CBC
            final byte[] iv = Arrays.copyOfRange(keyAndIv, this.keyLengthInByte, (this.keyLengthInByte + 16));
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        }

        final byte[] clear = cipher.doFinal(inBytes, 16, inBytes.length - 16);
        return new String(clear, StandardCharsets.UTF_8);
    }

    public String decryptWithPBKDF2(String encryptedBase64)
            throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException {
        return this.decryptWithPBKDF2(encryptedBase64, this.encryptionPassword, this.keyObtentionIterations);
    }

    public String decryptWithPBKDF2(String encryptedBase64, String password)
            throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException {
        return this.decryptWithPBKDF2(encryptedBase64, password, this.keyObtentionIterations);
    }

    private byte[] deriveKeyAndIv(final byte[] pass, final byte[] salt) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(this.digestAlgorithm);
        final byte[] passAndSalt = array_concat(pass, salt);
        byte[] hash = new byte[0];
        byte[] keyAndIv = new byte[0];
        for (int i = 0; i < 3 && keyAndIv.length < 48; i++) {
            final byte[] hashData = array_concat(hash, passAndSalt);
            hash = md.digest(hashData);
            keyAndIv = array_concat(keyAndIv, hash);
        }
        return keyAndIv;
    }

    private byte[] deriveKeyAndIvWithPBKDF2(String password, int hashIterations, final byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory keyFactory;
        if ("SHA-256".equals(this.digestAlgorithm)) {
            keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        } else {
            // MD5
            // Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/04-Testing_for_Weak_Encryption.html
            // "In addition, MD5 hash function is forbidden to be used with PBKDF2 such as PBKDF2WithHmacMD5."
            throw new UnsupportedOperationException("MD5 hash function is not supported with PBKDF2");
        }

        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, hashIterations, 48 * 8);
        return keyFactory.generateSecret(keySpec).getEncoded();
    }

    private byte[] array_concat(final byte[] a, final byte[] b) {
        final byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }


    public static void main(String[] args) throws Exception {
        String encrypted = "";

        // echo -n plainTextToEncrypt| openssl enc -base64 -aes-256-cbc -md sha256 -pass pass:secretKey -p
        // echo "U2FsdGVkX1922PzT8hlgGLWZWIBkNf/1PkAY6vw40+1yESqmk1+7L4hxSEgN3ygF"|openssl enc -aes-256-cbc -md sha256 -pass pass:secretKey -d -v -a
        AESUtil aes256Cbc = new AESUtil("AES/CBC/PKCS5Padding", "SHA-256", 256);
        File inputFile = new File("/tmp/hello.txt");
        File outputFile = new File("/tmp/hello.enc");
        // cat hello.enc|openssl enc -aes-256-cbc -d -md sha256 -pass pass:hello -p -pbkdf2
        aes256Cbc.encryptFile(inputFile, outputFile, "hello", true);
        encrypted = aes256Cbc.encryptString("plainTextToEncrypt", "secretKey");
        System.out.println("Encrypted aes-256-cbc sha256: " + encrypted + " , Decrypted: " + aes256Cbc.decrypt(encrypted, "secretKey"));

        // echo -n plainTextToEncrypt| openssl enc -base64 -aes-256-cbc -md sha256 -pass pass:secretKey -p -pbkdf2
//        encrypted = aes256Cbc.encryptStringWithPBKDF2("plainTextToEncrypt", "secretKey");
//        System.out.println("Encrypted aes-256-cbc sha256 pbkdf2: " + encrypted + ", Decrypted: " + aes256Cbc.decryptWithPBKDF2(encrypted, "secretKey"));
//
//        AESUtil aes128Cbc = new AESUtil("AES/CBC/PKCS5Padding", "SHA-256", 128);
//        encrypted = aes128Cbc.encryptString("plainTextToEncrypt", "secretKey");
//        System.out.println("Encrypted aes-128-cbc sha256: " + encrypted + " , Decrypted: " + aes128Cbc.decrypt(encrypted, "secretKey"));
//
//        encrypted = aes128Cbc.encryptStringWithPBKDF2("plainTextToEncrypt", "secretKey");
//        System.out.println("Encrypted aes-128-cbc sha256 pbkdf2: " + encrypted + ", Decrypted: " + aes128Cbc.decryptWithPBKDF2(encrypted, "secretKey"));

//        AESUtil aes256Ecb = new AESUtil("AES/ECB/PKCS5Padding", "SHA-256", 256);
//        encrypted = aes256Ecb.encryptString("plainTextToEncrypt", "secretKey");
//        System.out.println("Encrypted aes-256-ecb sha256: " + encrypted + " , Decrypted: " + aes256Ecb.decrypt(encrypted, "secretKey"));

        // echo -n plainTextToEncrypt| openssl enc -base64 -aes-256-cbc -md md5 -pass pass:secretKey -p
//        AESUtil aes256EcbMd5 = new AESUtil("AES/ECB/PKCS5Padding", "MD5", 256);
//        encrypted = aes256EcbMd5.encryptString("plainTextToEncrypt", "secretKey");
//        System.out.println("Encrypted aes-256-ecb md5: " + encrypted + " , Decrypted: " + aes256EcbMd5.decrypt(encrypted, "secretKey"));

        // Not supported 
        // encrypted = aes256EcbMd5.encryptStringWithPBKDF2("plainTextToEncrypt", "secretKey");
        // System.out.println("Encrypted aes-256-ecb md5 pbkdf2: " + encrypted + " , Decrypted: " + aes256EcbMd5.decryptWithPBKDF2(encrypted, "secretKey"));

    }
}
