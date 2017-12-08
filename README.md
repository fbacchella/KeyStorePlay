# An java SSL and security analyzer

This is a tool that help to debug java security and ssl context.

It's a command line tool that dump some informations.

The following information can be dumped with command line arguments:

 * --providers: do an introspections of all security providers available.
 * --services: it dumps all available security services.
 * --connect: it take a string host:port and try to do an ssl connection to this host, it dumps a few informations about the connections if it succeed.
 * --loadbc: it try to load BouncyCastle's providers.
 * --wildflyelytron: it try to load WildFly Elytron security provider.
 * --autoload: it try to load all providers declared as services (see http://docs.oracle.com/javase/8/docs/api/java/util/ServiceLoader.html)
 * --searchks: it searches for the default key stores.
 * --defaultssl: show details about the default SSL/TLS settings and security properties.
 * --keystore,  Dump the content of a keystore file.

 It's build using `maven package`  and then can be run with `java -jar target/keystoreplay.jar -h`
