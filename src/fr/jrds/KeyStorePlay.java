package fr.jrds;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.AccessController;
import java.net.URLClassLoader;
import java.nio.file.Paths;
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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;

import sun.security.pkcs11.SunPKCS11;

public class KeyStorePlay {


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

    @Parameter(names = {"--classpath", "-C"}, description = "Classpath to search for services")
    String classpath = null;

    private static final Set<Class<? extends Provider>> registredProvider = new HashSet<>();

    public static void main(String[] args) {
        for (Provider p: Security.getProviders()) {
            registredProvider.add(p.getClass());
        }
        try {
            for (String s: new String[] {"sun.security.jgss.wrapper.SunNativeProvider", "sun.security.jgss.SunProvider"}) {
                loadByName(s);
            }
        } catch (Exception | UnsupportedClassVersionError ex) {
            System.out.println("Missing some Sun's providers, not a Oracle JDK ? " + ex.getMessage());
        }
        tryPkcs11();
        
        try {
            @SuppressWarnings("unchecked")
            Class<Provider> clazz = (Class<Provider>) Class.forName("org.apache.wss4j.common.crypto.ThreadLocalSecurityProvider");
            if (! registredProvider.contains(clazz)) {
                clazz.getMethod("install").invoke(null);
                registredProvider.add(clazz);
                System.out.println("Loaded TLSP");
            }
        } catch (Exception | UnsupportedClassVersionError e) {
            System.out.println("Failed to add ThreadLocalSecurityProvider provider: " + e.getMessage());
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
        if (main.autoload) {
            loadservices(main.classpath);
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

    private static void loadservices(String classpath) {
        ClassLoader loader;
        if (classpath == null) {
            loader = KeyStorePlay.class.getClassLoader();
        } else {
            String[] paths = classpath.split(File.pathSeparator);
            URL[] urls = new URL[paths.length];
            for (int i = 0 ; i < paths.length ; i ++) {
                try {
                    urls[i] = Paths.get(paths[i]).toUri().toURL();
                } catch (MalformedURLException e) {
                    System.out.println(e.getMessage());
                }
            }
            loader = new URLClassLoader(urls);
            System.out.println(Arrays.toString(urls) + " " + loader);
        }
        System.out.println("*************");
        System.out.println("Register security provider declared as services");
        ServiceLoader<java.security.Provider> sl =  ServiceLoader.load(Provider.class, loader);
        for(Provider i: sl) {
            if (registredProvider.contains(i.getClass())) {
                continue;
            }
            System.out.format("%s: %s\n", i.getClass().getName(), locateJar(i.getClass()));
            System.out.println("    register " + i);
            try {
                Security.insertProviderAt(i, Security.getProviders().length);
            } catch (Exception ex) {
                System.out.println("Failed to add " + i.getName() + " providers as a service: " + ex.getMessage());
            }
        }
    }

    private static void loadbouncycastle() {
        try {
            loadByName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            loadByName("org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider");
            loadByName("org.bouncycastle.jsse.provider.BouncyCastleJsseProvider");
            System.out.println("Loaded BouncyCastle");
        } catch (Exception | UnsupportedClassVersionError e) {
            System.out.println("Failed to add BouncyCastle providers: " + e.getMessage());
        }
    }

    private static void loadwildflyelytron() {
        try {
            loadByName("org.wildfly.security.WildFlyElytronProvider");
            System.out.println("Loaded WildFly Elytron");
        } catch (Exception | UnsupportedClassVersionError e) {
            System.out.println("Failed to add WildFly Elytron provider: " + e.getMessage());
        }
    }

    private static void loadconscrypt() {
        try {
            loadByName("org.conscrypt.OpenSSLProvider");
            System.out.println("Loaded Google's conscrypt");
        } catch (Exception | UnsupportedClassVersionError e) {
            System.out.println("Failed to add Google's conscrypt provider: " + e.getMessage());
        }
    }

    private static void secprops() {
        System.out.println("*************");
        System.out.println("Current know security properties");
        for (String prop: new String[] {"java.security",
                                        "cert.provider.x509v",
                                        "crypto.policy", 
                                        "https.cipherSuites",
                                        "java.security.egd",
                                        "java.protocol.handler.pkgs",
                                        "javax.net.ssl.keyStore",
                                        "javax.net.ssl.keyStorePassword",
                                        "javax.net.ssl.keyStoreProvider",
                                        "javax.net.ssl.keyStoreType",
                                        "javax.net.ssl.trustStore",
                                        "javax.net.ssl.trustStoreType",
                                        "jdk.certpath.disabledAlgorithms",
                                        "jdk.jar.disabledAlgorithms",
                                        "jdk.security.allowNonCaAnchor",
                                        "jdk.security.useLegacyECC",
                                        "jdk.sasl.disabledMechanisms",
                                        "jdk.tls.disabledAlgorithms", 
                                        "jdk.tls.ephemeralDHKeySize",
                                        "jdk.tls.legacyAlgorithms", 
                                        "jdk.tls.keyLimits",
                                        "jdk.tls.namedGroups",
                                        "jsse.enableSNIExtension",
                                        "jceks.key.serialFilter",
                                        "securerandom.strongAlgorithms",
                                        "securerandom.source",
                                        "sun.security.ssl.allowLegacyHelloMessages",
                                        "ssl.KeyManagerFactory.algorithm",
                                        "ssl.TrustManagerFactory.algorithm",
                                        "ssl.SocketFactory.provider",
        }) {
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
        if (storeFile.endsWith(".p12") || storeFile.endsWith(".pfx")) {
            storeType = "PKCS12";
        } else if (storeFile.endsWith(".jks")) {
            storeType = "JKS";
        } else if (storeFile.endsWith(".ks")) {
            storeType = "JKS";
        } else if (storeFile.endsWith(".jceks")) {
            storeType = "JCEKS";
        } else if (storeFile.endsWith(".bks")) {
            storeType = "BKS";
        } else if (storeFile.endsWith(".policy")) {
            storeType = "DKS";
        } else if (storeFile.endsWith("cacerts")) {
            storeType = "JKS";
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

    @SuppressWarnings("restriction")
    public static void tryPkcs11() {
        if (! registredProvider.contains(SunPKCS11.class)) {
            StringBuilder buffer = new StringBuilder();
            buffer.append("name=NSS\n");
            buffer.append("nssDbMode=noDb\n");
            // Needs to use introspection because of API change
            try (ByteArrayInputStream bis = new ByteArrayInputStream(buffer.toString().getBytes())) {
                SunPKCS11 p = SunPKCS11.class.getConstructor(ByteArrayInputStream.class).newInstance(bis);
                Security.insertProviderAt(p, Security.getProviders().length + 1);
                registredProvider.add(p.getClass());
            } catch (Exception e) {
                System.out.println("Failed to add nss PKCS11 provider: " + e.getMessage());
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

    private static final Comparator<Entry<?, ?>> propsComparator = new Comparator<Entry<?, ?>>() {
        @Override
        public int compare(Entry<?, ?> o1,
                           Entry<?, ?> o2) {
            int c1 = o1.toString().compareTo(o2.toString());
            if (c1 == 0) {
                return o2.toString().compareTo(o2.toString());
            } else {
                return c1;
            }
        }
    };

    private static final Pattern PROPINFOPATTERN = Pattern.compile("^([A-Za-z0-9]+)\\.([#:_\\(\\)/A-Za-z0-9\\.-]+)(?: (.+))?$");
    private static final Pattern ALIASEPATTERN = Pattern.compile("^Alg\\.Alias\\.([A-Za-z0-9]+)\\.(.+)$");
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
        System.out.println(Arrays.asList(Security.getProviders()));
        for(Provider p: providers) {
            Map<String, Set<String>> services = new TreeMap<String, Set<String>>();
            System.out.println("**** " + p.getName());
            System.out.println("    " + p.getInfo());
            System.out.println("    " + p.getVersion());
            System.out.println("    location: " + p.getClass().getName() + "@" + locateJar(p.getClass()));
            for(Provider.Service s: p.getServices()) {
                if (! services.containsKey(s.getType())) {
                    services.put(s.getType(), new TreeSet<String>());
                }
                services.get(s.getType()).add(s.getAlgorithm());
            }
            List<Entry<Object, Object>> properties = new ArrayList<>(p.entrySet());
            Map<String, Map<String, Map<String, String>>> propsMap = new HashMap<>();
            Map<String, Map<String, Set<String>>> aliases = new HashMap<>();
            for (String service: services.keySet()) {
                propsMap.put(service, new HashMap<String, Map<String, String>>());
                aliases.put(service, new HashMap<String, Set<String>>());
            }
            if (properties.size() > 0) {
                Collections.sort(properties, propsComparator);
                for (Entry<Object, Object> e: properties) {
                    String propPath = e.getKey().toString();
                    try {
                        Matcher ma = ALIASEPATTERN.matcher(propPath);
                        if (ma.matches()) {
                            String propService = ma.group(1);
                            String propAlgorithm = ma.group(2);
                            if (! aliases.containsKey(propService)) {
                                aliases.put(propService, new HashMap<String, Set<String>>());
                            }
                            if (! aliases.get(propService).containsKey(e.getValue().toString())) {
                                aliases.get(propService).put(e.getValue().toString(), new HashSet<String>());
                            }
                            aliases.get(propService).get(e.getValue().toString()).add(propAlgorithm);
                        } else {
                            Matcher m = PROPINFOPATTERN.matcher(propPath);
                            if (m.matches()) {
                                String propService = m.group(1);
                                String propAlgorithm = m.group(2);
                                String propName = m.group(3);
                                if (propName == null) {
                                    propName = "Implementing class";
                                }
                                if (! propsMap.containsKey(propService)) {
                                    propsMap.put(propService, new HashMap<String, Map<String, String>>());
                                }
                                Map<String, Map<String, String>> algoProps = propsMap.get(propService);
                                if (! algoProps.containsKey(propAlgorithm)) {
                                    algoProps.put(propAlgorithm, new HashMap<String, String>());
                                }
                                algoProps.get(propAlgorithm).put(propName, e.getValue().toString());
                            } else {
                                System.out.format("not matching for %s\n", propPath);
                            }
                        }
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                }
            }
            propsMap.remove("Provider");
            System.out.println();
            for (Map.Entry<String, Set<String>> e: services.entrySet()) {
                System.out.format("    %s:\n", e.getKey());
                Map<String, Map<String, String>> algsProps = propsMap.remove(e.getKey());
                List<Entry<String, Map<String, String>>> algos = new ArrayList<>(algsProps.entrySet());
                Collections.sort(algos, propsComparator);
                Map<String, Set<String>> serviceAliases = aliases.get(e.getKey());
                for (Entry<String, Map<String, String>> a: algos) {
                    String algo = a.getKey();
                    Map<String, String> algoProps = a.getValue();
                    algoProps.remove("Implementing class");
                    algoProps.remove("ImplementedIn");
                    Set<String> algoAliases;
                    if (serviceAliases.containsKey(algo)) {
                        algoAliases = serviceAliases.get(algo);
                    } else {
                        algoAliases = Collections.emptySet();
                    }
                    System.out.format("        %s%s\n",
                                      algo,
                                      algoProps.isEmpty() ? "" : ":"
                                    );
                    if (! algoAliases.isEmpty()) {
                        System.out.format("            Aliases: %s\n", algoAliases);
                    }
                    for (Entry<String, String> prop: algoProps.entrySet()) {
                        System.out.format("            %s: %s\n", prop.getKey(), prop.getValue());
                    }
                }
            }
            if (propsMap.containsKey("Alg.Alias")) {
                System.out.format("\n    Aliases\n");
                for (Map.Entry<String, Map<String, String>> a: propsMap.remove("Alg.Alias").entrySet()) {
                    System.out.format("        %s -> %s\n", a.getKey(), a.getValue().get("Implementing class"));

                }
            }
            if (! propsMap.isEmpty()) {
                System.out.format("    %s:\n", propsMap);
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
    
    private static void loadByName(String providerClassName) throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        @SuppressWarnings("unchecked")
        Class<Provider> clazz = (Class<Provider>) Class.forName(providerClassName);
        if (! registredProvider.contains(clazz)) {
            Security.insertProviderAt(clazz.newInstance(), Security.getProviders().length);
            registredProvider.add(clazz);
        }
    }

}
