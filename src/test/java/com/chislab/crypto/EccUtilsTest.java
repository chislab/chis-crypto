package com.chislab.crypto;

import org.bouncycastle.util.encoders.Base64;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

/**
 * @author lpf
 * @create 2021-02-05 上午9:51
 */
public class EccUtilsTest {

    @Test
    public void testEccUtils() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException {
        final KeyPair keyPair = EccUtils.generateEccKeyPair();
        final PublicKey publicKey = keyPair.getPublic();
        final PrivateKey privateKey = keyPair.getPrivate();

        final String cipherText = EccUtils.eccEncrypt(publicKey, "Hello Chislab");
        final String plainText = EccUtils.eccDecrypt(privateKey, cipherText);

        Assert.assertTrue("Hello Chislab".equals(plainText));

        EccUtils.savePublicKey("keys/public.key", publicKey);
        EccUtils.savePrivateKey("keys/private.key", privateKey);

        final PublicKey publicKeyLoaded = EccUtils.loadPublicKey("keys/public.key");
        final PrivateKey privateKeyLoaded = EccUtils.loadPrivateKey("keys/private.key");

        System.out.println(Base64.toBase64String(publicKeyLoaded.getEncoded()));
        System.out.println(Base64.toBase64String(privateKeyLoaded.getEncoded()));
    }
}
