package com.changhong.chis.crypto;

import com.changhong.chis.crypto.util.ECCUtil;
import sun.security.provider.certpath.X509CertificatePair;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * @author ：hdj
 * @date ：Created in 2/4/21 5:05 PM
 * @description：
 * @modified By：
 * @version: $
 */
public class Test {
    public static void main(String[] args) throws Exception {
        KeyPair keyPair =  ECCUtil.getKeyPair();
        PrivateKey pk = keyPair.getPrivate();
        PublicKey pub = keyPair.getPublic();
        System.out.println(pk.getFormat());
        System.out.println(pub.getFormat());
//     = new X509CertificatePair().



        String a ="this is a context中文中文";
        byte[] encryptContext =  ECCUtil.publicEncrypt(a.getBytes(),pub);
        System.out.println(new String(encryptContext));
        byte[] originContext =  ECCUtil.privateDecrypt (encryptContext,pk);
        System.out.println(new String(originContext));
    }
}
