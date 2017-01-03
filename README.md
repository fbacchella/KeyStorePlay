# An java SSL and security analyzer

This is a tool that help to debug jave security and ssl context.

It's a command line tool that dump some informations.

The following information can be dumped with command line arguments:

 * -providers: do an introspections of all security providers available.
 * -services: it dumps all available services.
 * -connect: it take a string host:port and try to do an ssl connection to this host, it dumps a few informations about the connections if it succeed.
 * -loadbc: it try to load BouncyCastle's providers.
 * -autoload: it try to load all providers declared as services
 * -searchks: it searches for some default key stores.