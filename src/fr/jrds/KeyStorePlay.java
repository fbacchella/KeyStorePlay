package fr.jrds;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;


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
        System.out.println("*************");
        System.out.println("Register security provider declared as services");
        ServiceLoader<java.security.Provider> sl =  ServiceLoader.load(Provider.class);
        for(Provider i: sl) {
            System.out.println("    register " + i);
            Security.insertProviderAt(i, Security.getProviders().length + 1);
        }

        try {
            Security.insertProviderAt((Provider) Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider").newInstance(), Security.getProviders().length + 1);
            Security.insertProviderAt((Provider)Class.forName("org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider").newInstance(), Security.getProviders().length + 1);
        } catch (Exception e) {
            System.out.println("Failed to add BouncyCastle providers: " + e.getMessage());
        }

        try {
            StringBuilder buffer = new StringBuilder();
            buffer.append("name=NSS\n");
            buffer.append("nssDbMode=noDb\n");

            @SuppressWarnings("restriction")
            Provider p = new sun.security.pkcs11.SunPKCS11(new ByteArrayInputStream(buffer.toString().getBytes()));
            Security.insertProviderAt(p, Security.getProviders().length + 1);
        } catch (Exception e) {
            System.out.println("Failed to add nss PKCS11 provider: " + e.getMessage());
        }


        System.out.println("*************");
        System.out.println("Checking export policy");
        System.out.println("is restricted: " + KeyStorePlay.isRestricted());

        System.out.println("*************");
        System.out.println("checking default trust store");
        // Oracle official order for default trust store
        checkKeyStore(System.getProperty("javax.net.ssl.trustStore"));
        checkKeyStore(System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator + "jssecacerts");
        checkKeyStore(System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator + "cacerts");
        try {
            KeyStore appleKeyStore = KeyStore.getInstance("KeychainStore");
            appleKeyStore.load(null, "".toCharArray());
            System.out.println("KeychainStore");
            printKeyStoreInfo(appleKeyStore);
        } catch (KeyStoreException e) {
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Missing algorithm:" + e.getMessage());
        } catch (CertificateException e) {
            System.out.println("Invalid certificate:" + e.getMessage());
        } catch (IOException e) {
            System.out.println("Unable to laod Apple Keychain: " + e.getMessage());
        }
        enumerateProviders();
        enumerateServices();
        checkSSLContext();
        if(args.length > 0) {
            System.out.println("*************");
            System.out.println("Dumping some keystore");     
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

    }

    private static void checkKeyStore(String file) {
        if(file == null){
            return;
        }
        String cacertPath = "";
        try {
            KeyStore prodks = KeyStore.getInstance(KeyStore.getDefaultType());
            cacertPath = new File(file).getCanonicalPath();
            prodks.load(new FileInputStream(cacertPath), null);
            System.out.println(cacertPath);
            printKeyStoreInfo(prodks);
        } catch (KeyStoreException e) {
            System.out.println("invalid keystore:" + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Missing algorithm:" + e.getMessage());
        } catch (CertificateException e) {
            System.out.println("Invalid certificate:" + e.getMessage());
        } catch (FileNotFoundException e) {
        } catch (IOException e) {
            System.out.println("Unsuable cacerts file " + cacertPath + ":" + e.getMessage());
        }
    }

    private static void printKeyStoreInfo(KeyStore ks) throws KeyStoreException {
        System.out.println("  type: " + ks.getType());
        System.out.println("  provider: " + ks.getProvider().getName());
        System.out.println("  count: " + ks.size());        
    }

    private static void checkSSLContext() {
        System.out.println("*************");
        System.out.println("Checking sslparameters");
        try {
            SSLParameters params = SSLContext.getDefault().getSupportedSSLParameters();
            System.out.println("Supported:");
            System.out.println("  cipher suites: " + Arrays.toString(params.getCipherSuites()));
            System.out.println("  protocols: " + Arrays.toString(params.getProtocols()));
            System.out.println("Defaults:");
            params = SSLContext.getDefault().getDefaultSSLParameters();
            System.out.println("  providing class: " + SSLContext.getDefault().getServerSocketFactory().getClass());
            System.out.println("  cipher suites: " + Arrays.toString(params.getCipherSuites()));
            System.out.println("  protocols: " + Arrays.toString(params.getProtocols()));
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Missing algorithm:" + e.getMessage());
        }        
    }

    private static void enumerateProviders() {
        System.out.println("*************");
        System.out.println("Providers enumeration");
        Set<Provider> providers = new TreeSet<Provider>(new Comparator<Provider>(){
            @Override
            public int compare(Provider arg0, Provider arg1) {
                return arg0.getName().compareTo(arg1.getName());
            }
        });
        providers.addAll(Arrays.asList(Security.getProviders()));
        for(Provider p: providers) {
            Map<String, Set<String>> services = new TreeMap<String, Set<String>>();
            System.out.println("**** " + p.getName());
            System.out.println("    " + p.getInfo());
            System.out.println("    location: " + p.getClass().getName() + "@" + locateJar(p.getClass()));
            System.out.println();
            for(Provider.Service s: p.getServices()) {
                if (! services.containsKey(s.getType())) {
                    services.put(s.getType(), new TreeSet<String>());
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

}
