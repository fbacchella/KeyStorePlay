package fr.jrds;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class KeyStorePlay {

    // Make the javax.crypto.JceSecurity.isRestricted field visible,
    private static Method isRestricted = null;
    static {
        Class<?> jcJceSecurity;
        try {
            jcJceSecurity = Class.forName("javax.crypto.JceSecurity");
            Method m = jcJceSecurity.getDeclaredMethod("isRestricted");
            m.setAccessible(true);
        } catch (ClassNotFoundException e) {
        } catch (NoSuchMethodException e) {
        } catch (SecurityException e) {
        }
    }

    public static boolean isRestricted() {
        if(isRestricted != null) {
            try {
                return (Boolean) isRestricted.invoke(null);
            } catch (IllegalAccessException e) {
            } catch (IllegalArgumentException e) {
            } catch (InvocationTargetException e) {
            }
        }
        return false;
    }

    public static void main(String[] args) {

        Security.insertProviderAt(new BouncyCastleProvider(), 1);

        System.out.println("*************");
        System.out.println("Checking export policy");
        System.out.println("is restricted: " + KeyStorePlay.isRestricted());

        System.out.println("*************");
        System.out.println("Checking sslparameters");
        try {
            SSLParameters params = SSLContext.getDefault().getSupportedSSLParameters();
            System.out.println("cipher suites: " + Arrays.toString(params.getCipherSuites()));
            System.out.println("protocols: " + Arrays.toString(params.getProtocols()));
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Missing algorithm:" + e.getMessage());
        }
        System.out.println("*************");
        System.out.println("checking default cacerts");
        String cacertPath = "";
        try {
            KeyStore prodks = KeyStore.getInstance(KeyStore.getDefaultType());
            cacertPath = new File(System.getProperty("java.home")).getCanonicalPath() + File.separator + "lib" + File.separator + "security" + File.separator + "cacerts";
            prodks.load(new FileInputStream(cacertPath), null);
            System.out.println("type: " + prodks.getType());
            System.out.println("provider: " + prodks.getProvider().getName());
            System.out.println("count: " + prodks.size());
        } catch (KeyStoreException e) {
            System.out.println("invalid keystore:" + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Missing algorithm:" + e.getMessage());
        } catch (CertificateException e) {
            System.out.println("Invalid certificate:" + e.getMessage());
        } catch (FileNotFoundException e) {
            System.out.println("Missing cacerts file " + cacertPath + ":" + e.getMessage());
        } catch (IOException e) {
            System.out.println("Unsuable cacerts file " + cacertPath + ":" + e.getMessage());
        }

        checkStoreypes();
        enumerateProviders();
        enumerateServices();
        if(args.length > 0) {
            System.out.println("*************");
            System.out.println("Dumping some keystore");     
        }
        for(String storeFile: args) {
            String storeType = null;
            if(storeFile.endsWith("p12")) {
                storeType = "PKCS12";
            } else if(storeFile.endsWith("jks")) {
                storeType = "JKS";
            } else if(storeFile.endsWith("ks")) {
                storeType = "JKS";
            }
            if(storeType != null) {
                checkStore(storeFile, storeType);
            }
        }

    }

    private static void enumerateProviders() {
        System.out.println("*************");
        System.out.println("Providers enumeration");
        for(Provider p: Security.getProviders()) {
            Map<String, Set<String>> services = new HashMap<String, Set<String>>();
            System.out.println("**** " + p.getName());
            System.out.println("    " + p.getInfo());
            System.out.println("    " + p.getClass().getName() + "@" + locateJar(p.getClass()));
            for(Provider.Service s: p.getServices()) {
                if (! services.containsKey(s.getType())) {
                    services.put(s.getType(), new HashSet<String>());
                }
                services.get(s.getType()).add(s.getAlgorithm());
            }
            for(Map.Entry<String, Set<String>> e: services.entrySet()) {
                System.out.println("    " + e.getKey() +": " + e.getValue());
            }
        }
    }

    static private String locateJar(Class<?> c ) {
        String retValue="Not found";
        String cName = c.getName();
        int lastDot = cName.lastIndexOf('.');
        if(lastDot > 1) {
            String scn = cName.substring(lastDot + 1);
            URL jarUrl = c.getResource(scn + ".class");
            if(jarUrl != null)
                retValue = jarUrl.getPath();
            else
                retValue = scn + " not found";
        }
        return retValue.replaceFirst("!.*", "").replaceFirst("file:", "");
    }


    private static void enumerateServices() {
        System.out.println("*************");
        System.out.println("Services enumeration");
        Map<String, Map<String, List<String>>> services = new TreeMap<String, Map<String, List<String>>>();
        for(Provider p: Security.getProviders()) {
            for(Provider.Service s: p.getServices()) {
                if (! services.containsKey(s.getType())) {
                    services.put(s.getType(), new TreeMap<String, List<String>>());
                }
                if( ! services.get(s.getType()).containsKey(s.getAlgorithm()) ) {
                    services.get(s.getType()).put(s.getAlgorithm(), new ArrayList<String>());
                }
                services.get(s.getType()).get(s.getAlgorithm()).add(s.getProvider().getName());
            }
        }
        for(Entry<String, Map<String, List<String>>> e: services.entrySet()){
            System.out.println("**** " + e.getKey());
            for(Entry<String, List<String>> i: e.getValue().entrySet()) {
                System.out.println("    " + i.getKey() + ": " + i.getValue().toString());
            }
        }
    }    

    private static Set<String> getKeyStores() {
        Set<String> keyStores = new LinkedHashSet<String>();
        for(Provider p: Security.getProviders()) {
            for(Provider.Service s: p.getServices()) {
                if(s.getType() == "KeyStore")
                    keyStores.add(s.getAlgorithm());
            }
        }
        return keyStores;
    }

    private static void checkStoreypes() {
        System.out.println("*************");
        System.out.println("Trying keystore types");
        for(String ksName: getKeyStores()) {
            System.out.println("**** " + ksName);
            try {
                KeyStore ks = KeyStore.getInstance(ksName);
                ks.load(null, "".toCharArray());
                System.out.println("    provider: " + ks.getProvider().getName());
                System.out.println("    count: " + ks.size());
            }
            catch(Exception e) {
                System.out.println("Exception: " + e.getClass() + ": " + e.getMessage());
            }
        }

    }

    private static void checkStore(String f, String storeType) {
        try {
            KeyStore ks = KeyStore.getInstance(storeType);
            System.out.println("*** " + f + " ***");
            ks.load(new FileInputStream(f), "".toCharArray());
            System.out.println("type: " + ks.getType());
            System.out.println("provider: " + ks.getProvider().getName());
            System.out.println("count: " + ks.size());
            List<String> aliases = Collections.list(ks.aliases());
            System.out.println(aliases);
        } catch (Exception e) {
            System.out.println("Exception: " + e.getClass() + ": " + e.getMessage());
        }
    }

    private static void dumpLoaded(KeyStore ks) throws KeyStoreException {
        System.out.println("type: " + ks.getType());
        System.out.println("provider: " + ks.getProvider().getName());
        System.out.println("count: " + ks.size());
        List<String> aliases = Collections.list(ks.aliases());
        for(String alias: aliases) {
            try {
                if (ks.entryInstanceOf(alias, KeyStore.TrustedCertificateEntry.class)) {
                    System.out.println("certificate '" + alias + "'");
                    TrustedCertificateEntry entry = (TrustedCertificateEntry) ks.getEntry(alias, null);
                    System.out.println("    " + entry);
                }
                else if (ks.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
                    System.out.println("private key '" + alias + "'");                    
                    //KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, null);
                    KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, new KeyStore.PasswordProtection("qonrI8mB".toCharArray()));
                    System.out.println("    " + entry.getPrivateKey());
                    for(Certificate c: ks.getCertificateChain(alias)) {
                        System.out.println(c);                        
                    }
                }
                else if (ks.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class)) {
                    System.out.println("secret key '" + alias + "'");                    
                    KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) ks.getEntry(alias, new KeyStore.PasswordProtection("".toCharArray()));
                    System.out.println("    " + entry.getSecretKey().getFormat());
                }
                else {
                    System.out.println("Unknown alias type: '" + alias + "'");
                }
            } catch (Exception e) {
                System.out.println("Exception: " + e.getClass() + ": " + e.getMessage());
            }
        }

    }

}
