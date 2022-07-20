package com.example.messenger_android;

import android.util.Base64;
import android.util.Log;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypt {
    String TAG = "CRYPT";

    public Key RSApublicKey = null;
    private Key RSAprivateKey = null;

    public String sRSApublicKey = "";

    private String sessionKey = "";
    public String encodeSessionkey = "";

    public X509Certificate myCert;
    public PrivateKey certPrivate;
    public PublicKey certPublic;

    public X509Certificate otherCert;
    public X509Certificate otherCertPublic;

    /*============================================================================================*/
    /*  Constructor and helper functions */
    Crypt () {
        Security.removeProvider("BC");
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        RSAgenerateKey();
        KUZgenerateKey();
        generateGOST3410certificate();
    }

    private void getCiphList() {
        for (Provider provider: Security.getProviders()) {
            Log.i(TAG, provider.getName());
            for (Provider.Service s: provider.getServices()){
                if (s.getType().equals("Cipher"))
                    Log.i(TAG, "\t"+s.getType()+" "+ s.getAlgorithm());
            }
        }
    }

    public static byte[] decryptBASE64(String key){return Base64.decode(key, Base64.DEFAULT);}

    public static byte[] encodeUTF16(String string) {return string.getBytes(StandardCharsets.UTF_16);}

    public static String bytesToString(byte[] bytes) {
        byte[] tmpBytes = new byte[bytes.length + 1];
        tmpBytes[0] = 1;
        System.arraycopy(bytes, 0, tmpBytes, 1, bytes.length);
        return new BigInteger(tmpBytes).toString(36);
    }

    public static byte[] stringToBytes(String string) {
        byte[] tmpBytes = new BigInteger(string, 36).toByteArray();
        return Arrays.copyOfRange(tmpBytes, 1, tmpBytes.length);
    }

    public void setSessionKey (String newEncKey) throws Exception {
        encodeSessionkey = newEncKey;
        decryptSessionKey();
    }

    public String getSessionKey () {return sessionKey;}

    public void decryptSessionKey () throws Exception {
        sessionKey = decryptByPrivateRSA(encodeSessionkey);
    }

    /*============================================================================================*/
    /*  RSA  */
    public void RSAgenerateKey() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            KeyPair kp = kpg.genKeyPair();
            RSApublicKey = kp.getPublic();
            RSAprivateKey = kp.getPrivate();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        sRSApublicKey = new String(Base64.encode(RSApublicKey.getEncoded(), 0));
    }

    public static String encryptByPublicRSA(String key, String data) throws Exception {
        // Необходимо использовать правильную кодировку
        byte[] keyBytes = decryptBASE64(key);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Key publicKey = keyFactory.generatePublic(x509KeySpec);
        // Encode the original data with RSA public key
        byte[] encodedBytes = null;
        try {
            Cipher c = Cipher.getInstance("RSA");
            c.init(Cipher.ENCRYPT_MODE, publicKey);
            encodedBytes = c.doFinal(data.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return java.util.Base64.getEncoder().encodeToString(encodedBytes);
    }

    public String decryptByPrivateRSA(String encrypted){
        byte[] encrypted_bytes = java.util.Base64.getDecoder().decode(encrypted);
        byte[] decodedBytes = null;
        try {
            Cipher c = Cipher.getInstance("RSA");
            c.init(Cipher.DECRYPT_MODE, RSAprivateKey);
            decodedBytes = c.doFinal(encrypted_bytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return new String(decodedBytes);
    }

    /*============================================================================================*/
    /* GOST 34.12 */
    public void KUZgenerateKey() {
        // Set up secret key spec for 128-bit AES encryption and decryption
        SecretKeySpec sks = null;
        try {
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            sr.setSeed("random seed".getBytes());
            KeyGenerator kg = KeyGenerator.getInstance("GOST3412-2015");
            kg.init(256, sr);
            sks = new SecretKeySpec((kg.generateKey()).getEncoded(), "GOST3412-2015");

            sessionKey = new String (Base64.encode(sks.getEncoded(), Base64.DEFAULT));
            sks.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String KUZencrypt(String data) throws Exception {
        byte[] keyiv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] key = decryptBASE64(sessionKey);

        // Экземпляр секретного ключа SecretKeySpec создается для алгоритма "AES"
        SecretKeySpec skeySpec = new SecretKeySpec(key, "GOST3412-2015"); //new SecretKeySpec(digestOfPassword, "GOST3412-2015");
        Cipher cipher = Cipher.getInstance("GOST3412-2015/CBC/PKCS7Padding");
        IvParameterSpec ips = new IvParameterSpec(keyiv);

        try {
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ips); // Инициализация Cipher выполняется вызовом его метода init
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        byte[] encrypted = new byte[0]; // Для шифрования и дешифрования данных с помощью экземпляра Cipher, используется один из методов update() или doFinal().
        try {
            encrypted = cipher.doFinal(encodeUTF16(data));
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return bytesToString(encrypted);
    }

    public String KUZdecrypt(String data) throws Exception
    {
        byte[] keyiv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

        SecretKeySpec skeySpec = new SecretKeySpec(decryptBASE64(sessionKey), "GOST3412-2015"); //new SecretKeySpec(digestOfPassword, "GOST3412-2015");
        Cipher cipher = Cipher.getInstance("GOST3412-2015/CBC/PKCS7Padding");
        IvParameterSpec ips = new IvParameterSpec(keyiv);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, ips);
        byte[] decrypted = cipher.doFinal(stringToBytes(data));
        return new String(decrypted, StandardCharsets.UTF_16);
    }

    /*============================================================================================*/
    /* GOST 34.10 */
    public void generateGOST3410certificate(){
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            KeyPairGenerator keygen = KeyPairGenerator.getInstance("ECGOST3410-2012", "BC");
            keygen.initialize(new ECGenParameterSpec("Tc26-Gost-3410-12-512-paramSetA"));

            KeyPair keyPair = keygen.generateKeyPair();

            org.bouncycastle.asn1.x500.X500Name subject = new org.bouncycastle.asn1.x500.X500Name("CN=test");
            org.bouncycastle.asn1.x500.X500Name issuer = subject; // self-signed
            BigInteger serial = BigInteger.ONE; // serial number for self-signed does not matter a lot
            Date notBefore = new Date();
            Date notAfter = new Date(notBefore.getTime() + TimeUnit.DAYS.toMillis(365));


            X500NameBuilder builder = new X500NameBuilder(RFC4519Style.INSTANCE);
            builder.addRDN(RFC4519Style.c, "RU");
            builder.addRDN(RFC4519Style.o, "none");
            builder.addRDN(RFC4519Style.l, "none");
            builder.addRDN(RFC4519Style.st, "user");
            builder.addRDN(PKCSObjectIdentifiers.pkcs_9_at_emailAddress, "test@cert.ru");

            org.bouncycastle.cert.X509v3CertificateBuilder certificateBuilder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                    builder.build(), serial,
                    notBefore, notAfter,
                    subject, keyPair.getPublic()
            );

            org.bouncycastle.cert.X509CertificateHolder certificateHolder = certificateBuilder.build(
                    new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("GOST3411WITHGOST3410-2012-512")
                            .build(keyPair.getPrivate())
            );
            org.bouncycastle.cert.jcajce.JcaX509CertificateConverter certificateConverter = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter();

            X509Certificate cert = certificateConverter.getCertificate(certificateHolder);
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            System.out.println(privateKey.toString());
            System.out.println(publicKey.toString());

            System.out.println("\tCertificate for: " + cert.getSubjectDN());
            System.out.println("\tCertificate issued by: " + cert.getIssuerDN());
            System.out.println("\tThe certificate is valid from " + cert.getNotBefore() + " to "
                    + cert.getNotAfter());
            System.out.println("\tCertificate SN# " + cert.getSerialNumber());
            System.out.println("\tGenerated with " + cert.getSigAlgName());

            System.out.println("\n" + cert.toString());
            System.out.println(privateKey.toString());
            System.out.println(publicKey.toString());

            myCert = cert;
            certPrivate = privateKey;
            certPublic = publicKey;

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String sigData (String sData){
        byte[] data = encodeUTF16(sData);
        CMSProcessableByteArray msg = new CMSProcessableByteArray(data);

        List certList = new ArrayList();
        certList.add(myCert);

        try {
            Store certs = new JcaCertStore(certList);
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("GOST3411WITHGOST3410-2012-512").build(certPrivate);

            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(signer, myCert));
            gen.addCertificates(certs);
            CMSSignedData sigData = gen.generate(msg, false);

            return bytesToString(sigData.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public Boolean checkSig(String sData, String sSignature) {
        byte[] data = encodeUTF16(sData);
        byte[] signature = stringToBytes(sSignature);

        CMSProcessable signedContent = new CMSProcessableByteArray(data);
        CMSSignedData signedData;
        SignerInformation signer;

        try {
            signedData = new CMSSignedData(signedContent, signature);

            Store<X509CertificateHolder> certStoreInSing = signedData.getCertificates();
            signer = signedData.getSignerInfos().getSigners().iterator().next();

            Collection certCollection = certStoreInSing.getMatches(signer.getSID());
            Iterator certIt = certCollection.iterator();

            X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
            X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certHolder);

            return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certificate));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
