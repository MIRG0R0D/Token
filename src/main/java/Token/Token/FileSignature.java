package Token.Token;


import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import sun.security.pkcs11.SunPKCS11;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;

public class FileSignature {

    public FileSignature() {
    }

    public  FileSignature(File keyStoreFile) {
        this.keyStoreFile = keyStoreFile;
    }

    public static void printByte(byte[] b) {
        System.out.println("byte link "+b);
        for (byte a : b) {
            System.out.print(a + " ");
        }
        System.out.println();
    }

    private File keyStoreFile;
    private String password;
    private PrivateKey privateKey;
    private String certAlias;
    private String keyStoreTyp;
    
    public X509CertificateHolder getCert() throws GeneralSecurityException, IOException {
        KeyStore keystore = getKeystore(password.toCharArray());
        java.security.cert.Certificate c = keystore.getCertificate(certAlias);
        if (c == null) {
            System.out
                    .println("Chyba - nenalezen certifikat s aliasem >" + certAlias + "<  v ulozisti " + keyStoreFile);
            System.out.println("-- Seznam dostupnych aliasu certifikatu v ulozisti: ");
            Enumeration enumeration = keystore.aliases();
            while (enumeration.hasMoreElements()) {
                String alias = (String) enumeration.nextElement();
                System.out.println("---- alias name: " + alias);
            }
            System.out.println("-- done ");
        }
        return new X509CertificateHolder(c.getEncoded());
    }

    public PrivateKey getPrivateKey() throws GeneralSecurityException, IOException {
        if (privateKey == null) {
            privateKey = initalizePrivateKey();
        }
        return privateKey;
    }

    // Method to retrieve the PrivateKey form the KeyStore
    private PrivateKey initalizePrivateKey() throws GeneralSecurityException, IOException {
        KeyStore keystore = getKeystore(password.toCharArray());
        return (PrivateKey) keystore.getKey(certAlias, password.toCharArray());
    }

    private PublicKey initalizePublicKey() throws GeneralSecurityException, IOException {
        KeyStore keystore = getKeystore(password.toCharArray());
        PublicKey publicKey = null;
        Key key = keystore.getKey("root", password.toCharArray());
        if (key instanceof PrivateKey) {
            Certificate cert = keystore.getCertificate("root");
            // Get public key
             publicKey = cert.getPublicKey();


        }
        return publicKey;
    }

    private KeyStore  getKeystore(char[] password) throws GeneralSecurityException, IOException {
        // preferred keystore type impl. available in the env
        KeyStore keystore = KeyStore.getInstance(keyStoreTyp);
        InputStream input = new FileInputStream(keyStoreFile);
        try {
            keystore.load(input, password);
        } catch (IOException e) {
            // Catch the Exception
            System.out.println("Chyba - nenalezen soubor s certifikatem " + keyStoreFile + " " + e.getMessage());
        } finally {
            if (input != null) {
                input.close();
            }
        }
        return keystore;
    }

    public byte[] sign(byte[] file, String keyStoreUrl, String heslo, String alias, String keyStoreType)
            throws GeneralSecurityException, CMSException, IOException, OperatorCreationException {

        if (file == null || keyStoreType == null || keyStoreUrl == null || heslo == null || alias == null) {
            throw new IllegalArgumentException(
                    "Parametry: URL souboru, URL keystoru, heslo, alias a typ kestoru jsou povinne");
        }
        byte[] tempFile = file;
        keyStoreFile = new File(keyStoreUrl);
        password = heslo;
        certAlias = alias;
        keyStoreTyp = keyStoreType;

        List<X509CertificateHolder> certList = new ArrayList<X509CertificateHolder>();
        CMSTypedData msg = new CMSProcessableByteArray(file); // Data to sign

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        certList.add(getCert()); // Adding the X509 Certificate

        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        // Initializing the the BC's Signer
        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC")
                .build(getPrivateKey());

        gen.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                        .build(sha1Signer, getCert()));
        // adding the certificate
        gen.addCertificates(certs);
        // Getting the signed data
        CMSSignedData sigData = gen.generate(msg, true);

        
        //Sasha start 
        
        
//        String config = "";
//        SunPKCS11 provider = new SunPKCS11(config);
 //       System.out.println(   verify(sigData, getCert()));

/*
//        ==========================OPEN ANOTHE KEYSTORE TO RESIEVE ANOTHER CERTIFICATE AND GOT VERIFY=FALSE =====================================================================================================================
        String keyStoreTyp2 = "PKCS12";
        String keyStoreFile2 = "C:/usb/myp12file.p12";
        String password2 = "changeit";
        String certAlias2 = "root";

        KeyStore keystore = KeyStore.getInstance(keyStoreTyp2);
        InputStream input = new FileInputStream(keyStoreFile2);
        try {
            keystore.load(input, password2.toCharArray());
        } catch (IOException e) {
            // Catch the Exception
            System.out.println("Chyba - nenalezen soubor s certifikatem " + keyStoreFile2 + " " + e.getMessage());
        } finally {
            if (input != null) {
                input.close();
            }
        }

        java.security.cert.Certificate c = keystore.getCertificate(certAlias2);
        if (c == null) {
            System.out
                    .println("Chyba - nenalezen certifikat s aliasem ");
            System.out.println("-- Seznam dostupnych aliasu certifikatu v ulozisti: ");
            Enumeration enumeration = keystore.aliases();
            while (enumeration.hasMoreElements()) {
                String alias1= (String) enumeration.nextElement();
                System.out.println("---- alias name: " + alias1);
            }
            System.out.println("-- done ");
        }
        X509CertificateHolder certificateHolderCer= new X509CertificateHolder(c.getEncoded());
//        ==========================OPEN ANOTHE KEYSTORE TO RESIEVE ANOTHER CERTIFICATE AND GOT VERIFY=FALSE =====================================================================================================================

        System.out.println( verify(sigData, certificateHolderCer));
*/
        byte[] signedFile = sigData.getEncoded();

        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initVerify(initalizePublicKey());
        signature.update(signedFile);
        System.out.println(signature.verify(tempFile));

        Security.addProvider(new BouncyCastleProvider()); // <-- IMPORTANT!!! This will add BouncyCastle as provider in Java Security
        PrivateKey privateKey = initalizePrivateKey(); // This is located on src/main/resources/key/private2.pem
        PublicKey publicKey = initalizePublicKey();

         signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initVerify(publicKey);
        signature.update(signedFile);
        System.out.println(signature.verify(tempFile));



//        CMSSignedData cmsSignedData2 = new CMSSignedData(signedFile);

//        try{
//            CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(Data_Bytes), Sig_Bytes);
//            CertStore certStore = cms.getCertificatesAndCRLs("Collection", "BC");
//            SignerInformationStore signers = cms.getSignerInfos();
//            Collection c = signers.getSigners();
//            Iterator it = c.iterator();
//            while (it.hasNext()) {
//                SignerInformation signer = (SignerInformation) it.next();
//                Collection certCollection = certStore.getCertificates(signer.getSID());
//                Iterator certIt = certCollection.iterator();
//                X509Certificate cert = (X509Certificate) certIt.next();
////                cert_signer=cert;
//                System.out.println(signer.verify(cert, "BC"));            }
//        }catch(Exception e){
//            e.printStackTrace();
//
//        }

        
        
        //Sasha finished 

        return sigData.getEncoded();
    }

    public boolean verify(CMSSignedData sigData, X509CertificateHolder certificateHolder ){

        Collection<SignerInformation> signers = sigData.getSignerInfos().getSigners();
        X509CertificateHolder ch = null;
        try {
            ch = new X509CertificateHolder(certificateHolder.getEncoded());
            for (SignerInformation si : signers)
                if (si.getSID().match(ch))
                    if (si.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(ch))){
                   return true;
                    }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (CMSException e) {
            e.printStackTrace();
        }
        return false;
    }

    public byte[] signByUsbToken(byte[] file, String config) throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        SunPKCS11 provider = new SunPKCS11(config);
        Security.addProvider(provider);

        KeyStore keyStore = KeyStore.getInstance("pkcs11");
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(
                "Authentication", null);
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);

            signature.update(file);


        byte[] signatureValue = signature.sign();

//        p = p.configure(configName);


        return null;
    }
  
}
