package fr.jrds;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.security.AccessController;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Permission;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;

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

    @Parameter(names = {"--providers", "-p"}, description = "List known security provides")
    boolean providers = false;

    @Parameter(names = {"--services", "-s"}, description = "List known security services")
    boolean services = false;

    @Parameter(names = {"--connect", "-c"}, description = "Try a ssl/tls connection")
    String destination = null;

    @Parameter(names = {"--keystore", "-k"}, description = "Dump the content of a keystore")
    String keystore = null;

    @Parameter(names = {"--securityproperties", "-P"}, description = "List defined security properties")
    boolean secprops = false;

    @Parameter(names = {"--enumeratetls", "-t"}, description = "Enumerate ssl/tls settings")
    boolean enumeratessl = false;

    @Parameter(names = {"--loadbc", "-b"}, description = "Add BouncyCastle security provider")
    boolean bouncycastle = false;

    @Parameter(names = {"--wildflyelytron", "-w"}, description = "Add WildFly Elytron security provider")
    boolean wildflyelytron = false;

    @Parameter(names = {"--conscrypt", "-g"}, description = "Add Google's conscrypt security provider")
    boolean conscrypt = false;

    @Parameter(names = {"--autoload", "-a"}, description = "Autoload security services defined in MANIFEST.mf")
    boolean autoload = false;

    @Parameter(names = {"--searchks", "-K"}, description = "Search in keystores")
    boolean searchks = false;

    @Parameter(names = {"--help", "-h"}, help = true)
    private boolean help;

    public static void main(String[] args) {
        try {
            Security.insertProviderAt((Provider)Class.forName("sun.security.jgss.wrapper.SunNativeProvider").newInstance(), Security.getProviders().length + 1);
            Security.insertProviderAt((Provider)Class.forName("sun.security.jgss.SunProvider").newInstance(), Security.getProviders().length + 1);
        } catch (InstantiationException | IllegalAccessException
                        | ClassNotFoundException e) {
            System.out.println("Missing some Sun's providers, not a Oracle JDK ? " + e.getMessage());
        }

        KeyStorePlay main = new KeyStorePlay();
        JCommander jcom = JCommander
                        .newBuilder()
                        .addObject(main)
                        .build();

        try {
            jcom.parse(args);
        } catch (ParameterException e) {
            System.err.println(e.getMessage());
        }
        if (main.help) {
            jcom.usage();
            System.exit(0);
        }
        if (main.bouncycastle) {
            loadbouncycastle();
        }
        if (main.wildflyelytron) {
            loadwildflyelytron();
        }
        if (main.conscrypt) {
            loadconscrypt();
        }
        if (main.autoload) {
            loadservices();
        }
        if (main.providers) {
            enumerateProviders();
        }
        if (main.services) {
            enumerateServices();
        }
        if (main.destination != null) {
            connect(main.destination);
        }
        if (main.keystore != null) {
            dumpKeyStore(main.keystore);
        }
        if (main.secprops) {
            secprops();
        }
        if (main.enumeratessl) {
            enumeratessl();
        }
        if (main.searchks) {
            searchks();
        }

    }

    private static void searchks() {
        System.out.println("*************");
        System.out.println("checking default trust store");
        // Oracle official order for default trust store
        checkKeyStore(System.getProperty("javax.net.ssl.trustStore"), System.getProperty("javax.net.ssl.trustStoreType", KeyStore.getDefaultType()));
        checkKeyStore(System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator + "jssecacerts", "jks");
        checkKeyStore(System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator + "cacerts", "jks");
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
            System.out.println("Unable to load Apple Keychain: " + e.getMessage());
        }
    }

    private static void loadservices() {
        System.out.println("*************");
        System.out.println("Register security provider declared as services");
        ServiceLoader<java.security.Provider> sl =  ServiceLoader.load(Provider.class);
        for(Provider i: sl) {
            System.out.println("    register " + i);
            try {
                Security.insertProviderAt(i, Security.getProviders().length + 1);
            } catch (Exception e) {
                System.out.println("Failed to add " + i.getName() + " providers as a service: " + e.getMessage());
            }
        }
    }

    private static void loadbouncycastle() {
        try {
            Security.insertProviderAt((Provider) Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider").newInstance(), Security.getProviders().length + 1);
            Security.insertProviderAt((Provider)Class.forName("org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider").newInstance(), Security.getProviders().length + 1);
            System.out.println("Loaded BouncyCastle");
        } catch (Exception e) {
            System.out.println("Failed to add BouncyCastle providers: " + e.getMessage());
        }
    }

    private static void loadwildflyelytron() {
        try {
            Security.insertProviderAt((Provider) Class.forName("org.wildfly.security.WildFlyElytronProvider").newInstance(), Security.getProviders().length + 1);
            System.out.println("Loaded WildFly Elytron");
        } catch (Exception e) {
            System.out.println("Failed to add WildFly Elytron provider: " + e.getMessage());
        }
    }

    private static void loadconscrypt() {
        try {
            Security.insertProviderAt((Provider) Class.forName("org.conscrypt.OpenSSLProvider").newInstance(), Security.getProviders().length + 1);
            System.out.println("Loaded Google's conscrypt");
        } catch (Exception e) {
            System.out.println("Failed to add Google's conscrypt provider: " + e.getMessage());
        }
    }

    private static void secprops() {
        System.out.println("*************");
        System.out.println("Current know security properties");
        for (String prop: new String[] {"java.security",
                                        "crypto.policy", 
                                        "cert.provider.x509v", 
                                        "java.protocol.handler.pkgs",
                                        "ssl.SocketFactory.provider",
                                        "javax.net.ssl.keyStore",
                                        "javax.net.ssl.keyStorePassword",
                                        "javax.net.ssl.keyStoreProvider",
                                        "javax.net.ssl.keyStoreType",
                                        "javax.net.ssl.trustStore",
                                        "javax.net.ssl.trustStoreType",
                                        "ssl.KeyManagerFactory.algorithm",
                                        "ssl.TrustManagerFactory.algorithm",
                                        "jdk.certpath.disabledAlgorithms",
                                        "jdk.jar.disabledAlgorithms",
                                        "jdk.tls.disabledAlgorithms", 
                                        "jdk.tls.legacyAlgorithms", 
                                        "jsse.enableSNIExtension",
                                        "https.cipherSuites",
                                        "sun.security.ssl.allowLegacyHelloMessages",
                                        "jdk.tls.ephemeralDHKeySize",
                                        "jceks.key.serialFilter"}) {
            String value = java.security.Security.getProperty(prop);
            if (value != null) {
                System.out.format("%s=%s\n", prop, value);
            }
        }
    }

    private static void enumeratessl() {
        System.out.println("*************");
        System.out.println("Enumerating SSL context parameters");

        Map<String, List<String>> providers = new TreeMap<>();
        Map<String, String> defaultprotos = new HashMap<>();
        for(Provider p: Security.getProviders()) {
            List<String> contexts = new ArrayList<>();
            for(Provider.Service s: p.getServices()) {
                if ("SSLContext".equals(s.getType())) {
                    contexts.add(s.getAlgorithm());
                }
            }
            if (contexts.size() > 0) {
                providers.put(p.getName(), contexts);
            }
        }
        for (Entry<String, List<String>> p: providers.entrySet()) {
            System.out.println("**** " + p.getKey());
            for (String a: p.getValue()) {
                System.out.println("  " + a + (a.equals(defaultprotos.get(p.getKey())) ? " (default)" : ""));
                try {
                    SSLContext ctx = SSLContext.getInstance(a, p.getKey());
                    if ( ! "Default".equals(a)) {
                        ctx.init(null, null, null);
                    }
                    SSLParameters defaultparams = ctx.getDefaultSSLParameters();
                    SSLParameters supportedparams = ctx.getSupportedSSLParameters();

                    System.out.println("    SSL/TLS socket providing class: " + ctx.getServerSocketFactory().getClass());

                    System.out.println("    Default protocols:");
                    System.out.println("      " + getProtocols(defaultparams));
                    System.out.println("    Supported protocols:");
                    System.out.println("      " + getProtocols(supportedparams));
                    System.out.println("    Defaults cipher suites:");
                    for(String c: defaultparams.getCipherSuites()) {
                        System.out.println("      " + c);
                    }
                    System.out.println("    Supported cipher suites:");
                    for(String c: supportedparams.getCipherSuites()) {
                        System.out.println("      " + c);
                    }
                } catch (NoSuchAlgorithmException | NoSuchProviderException | IllegalStateException | KeyManagementException e) {
                    e.printStackTrace();
                }

            }
        }
    }

    private static String getProtocols(SSLParameters params) {
        String protocols = Arrays.toString(params.getProtocols());
        return protocols.substring(1,  protocols.length() -1);
    }

    public static void dumpKeyStore(String storeFile) {
        System.out.println("*************");
        System.out.println("Dumping keystore " + storeFile);
        String storeType = null;
        if (storeFile.endsWith("p12") || storeFile.endsWith("pfx")) {
            storeType = "PKCS12";
        } else if (storeFile.endsWith("jks")) {
            storeType = "JKS";
        } else if (storeFile.endsWith("ks")) {
            storeType = "JKS";
        } else if (storeFile.endsWith("jceks")) {
            storeType = "JCEKS";
        } else if (storeFile.endsWith("bks")) {
            storeType = "BKS";
        } else if (storeFile.endsWith("policy")) {
            storeType = "DKS";
        }
        if (storeType != null) {
            checkStore(storeFile, storeType);
        }
    }

    public static void connect(String cnxString) {
        System.out.println("*************");
        System.out.println("Connecting to " + cnxString);
        try {
            String[] cnxInfoString = cnxString.split(":");
            if (cnxInfoString.length != 2) {
                return;
            }
            String host = cnxInfoString[0];
            int port = Integer.parseInt(cnxInfoString[1]);
            SSLSocketFactory factory =  (SSLSocketFactory) SSLSocketFactory.getDefault();
            try (SSLSocket socket =  (SSLSocket) factory.createSocket(host, port)) {
                SSLSession session = socket.getSession();
                System.out.printf("connect to %s as '%s', using %s\n", cnxString, session.getPeerPrincipal(), session.getCipherSuite());
            }
        } catch (NumberFormatException | IOException e) {
            System.out.println("connection failed: " +  e.getMessage());
        }
    }

    public static void providers() {

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

        enumerateProviders();
        enumerateServices();

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

    private static void checkKeyStore(String file, String storeType) {
        if(file == null){
            return;
        }
        String cacertPath = "";
        try {
            KeyStore prodks = KeyStore.getInstance(storeType);
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

}
