package com.chislab.crypto;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.*;
import java.security.spec.*;

/**
 * @author lpf
 * @create 2021-02-05 上午9:36
 */
public class EccUtils {
    public static KeyPair generateEccKeyPair() throws InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        // add provider
        Security.addProvider(new BouncyCastleProvider());

        // generate key pair
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();

        return keyPair;
    }

    /**
     *
     * @param publicKey
     * @param plainText
     * @return Base64 encoding string
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String eccEncrypt(PublicKey publicKey, String plainText) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        final Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        final byte[] bytes = cipher.doFinal(plainText.getBytes());

        return Base64.toBase64String(bytes);
    }

    /**
     *
     * @param privateKey
     * @param cipherText
     * @return string
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     */
    public static String eccDecrypt(PrivateKey privateKey, String cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        final Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        final byte[] bytes = cipher.doFinal(Base64.decode(cipherText));

        return new String(bytes);
    }

    /**
     *
     * @param keyPath
     * @param publicKey
     * @throws IOException
     */
    public static void savePublicKey(String keyPath, PublicKey publicKey) throws IOException {
        final String data = Base64.toBase64String(publicKey.getEncoded());
        FileUtils.writeStringToFile(new File(keyPath), data, Charset.forName("UTF-8"));
    }

    /**
     *
     * @param keyPath
     * @param privateKey
     * @throws IOException
     */
    public static void savePrivateKey(String keyPath, PrivateKey privateKey) throws IOException {
        final String data = Base64.toBase64String(privateKey.getEncoded());
        FileUtils.writeStringToFile(new File(keyPath), data, Charset.forName("UTF-8"));
    }

    /**
     *
     * @param keyPath
     * @return publicKey object
     * @throws IOException
     */
    public static PublicKey loadPublicKey(String keyPath) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        final String publicKeyString = FileUtils.readFileToString(new File(keyPath), Charset.forName("UTF-8"));
        // 创建keyFactory
        final KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        // 创建privateKey规则
        final X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.decode(publicKeyString));
        // 获取、返回privateKey
        final PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);

        return publicKey;
    }

    /**
     *
     * @param keyPath
     * @return privateKey object
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PrivateKey loadPrivateKey(String keyPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        final String privateKeyString = FileUtils.readFileToString(new File(keyPath), Charset.forName("UTF-8"));
        // 创建keyFactory
        final KeyFactory keyFactory = KeyFactory.getInstance("EC");
        // 创建privateKey规则
        final PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.decode(privateKeyString));
        // 获取、返回privateKey
        final PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

        return privateKey;
    }

}
