package org.logstash.plugins.inputs.http.util;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import javax.crypto.Cipher;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocketFactory;

public class SslSimpleBuilder implements SslBuilder {

    private final static Logger LOGGER = LogManager.getLogger(SslSimpleBuilder.class);

    public static final Set<String> SUPPORTED_CIPHERS = new HashSet<>(Arrays.asList(
        ((SSLServerSocketFactory) SSLServerSocketFactory.getDefault()).getSupportedCipherSuites()
    ));

    /*
    Ciphers Compatibility List from https://wiki.mozilla.org/Security/Server_Side_TLS
    */
    private final static String[] DEFAULT_CIPHERS;
    static {
        String[] defaultCipherCandidates = new String[] {
            // Modern compatibility
            "TLS_AES_256_GCM_SHA384", // TLS 1.3
            "TLS_AES_128_GCM_SHA256", // TLS 1.3
            "TLS_CHACHA20_POLY1305_SHA256", // TLS 1.3 (since Java 11.0.14)
            // Intermediate compatibility
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", // (since Java 11.0.14)
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", // (since Java 11.0.14)
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            // Backward compatibility
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
        };
        DEFAULT_CIPHERS = Arrays.stream(defaultCipherCandidates).filter(SUPPORTED_CIPHERS::contains).toArray(String[]::new);
    }

    private final static String[] DEFAULT_CIPHERS_LIMITED = new String[] {
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
    };

    private String[] ciphers = getDefaultCiphers();

    private final ServerSslContextBuilderFactory serverSslContextBuilderFactory;
    private SslContextBuilderTrustConfigurator sslContextBuilderTrustConfigurator;

    private SslSimpleBuilder(final ServerSslContextBuilderFactory serverSslContextBuilderFactory) {
        this.serverSslContextBuilderFactory = serverSslContextBuilderFactory;
    }

    public static SslSimpleBuilder serverFromKeystore(final String keystorePath, final String keystorePassword) {
        LOGGER.debug("SERVER FROM KEYSTORE({})", keystorePath);
        final ServerSslContextBuilderFactory serverSslContextBuilderFactory = new ServerSslContextBuilderFactory.FromKeyStore(keystorePath, keystorePassword);
        return new SslSimpleBuilder(serverSslContextBuilderFactory);
    }

    public static SslSimpleBuilder serverFromCertificate(final String certificateFilePath, final String keyFilePath, final String passPhrase) {
        LOGGER.debug("SERVER FROM CERTIFICATE/KEY PAIR ({})/({}})\n", certificateFilePath, keyFilePath);

        final ServerSslContextBuilderFactory serverSslContextBuilderFactory = new ServerSslContextBuilderFactory.FromCertificateKeyPair(certificateFilePath, keyFilePath, passPhrase);
        return new SslSimpleBuilder(serverSslContextBuilderFactory);
    }

    public SslSimpleBuilder setCipherSuites(String[] ciphersSuite) throws IllegalArgumentException {
        for (String cipher : ciphersSuite) {
            if (SUPPORTED_CIPHERS.contains(cipher)) {
                LOGGER.debug("{} cipher is supported", cipher);
            } else {
                if (!isUnlimitedJCEAvailable()) {
                    LOGGER.warn("JCE Unlimited Strength Jurisdiction Policy not installed");
                }
                throw new IllegalArgumentException("Cipher `" + cipher + "` is not available");
            }
        }

        ciphers = ciphersSuite;
        return this;
    }

    public SslSimpleBuilder setCertificateAuthorities(String[] certs) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("SETTING TRUST CONFIGURATOR -> CERTIFICATE AUTHORITIES({})", Arrays.asList(certs));
        }
        return setTrustConfigurator(new SslContextBuilderTrustConfigurator.FromCertificateAuthorities(certs));
    }

    private synchronized SslSimpleBuilder setTrustConfigurator(final SslContextBuilderTrustConfigurator trustConfigurator) {
        if (Objects.nonNull(this.sslContextBuilderTrustConfigurator)) {
            throw new IllegalStateException("trust configurator already defined");
        }
        this.sslContextBuilderTrustConfigurator = trustConfigurator;
        return this;
    }

    public SslContext build() throws Exception {
        SslContextBuilder builder = serverSslContextBuilderFactory.init();

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Available ciphers: " + SUPPORTED_CIPHERS);
            LOGGER.debug("Ciphers:  " + Arrays.toString(ciphers));
        }

        builder.ciphers(Arrays.asList(ciphers));

        if (Objects.nonNull(sslContextBuilderTrustConfigurator)) {
            sslContextBuilderTrustConfigurator.apply(builder);
        }

        return doBuild(builder);
    }

    // NOTE: copy-pasta from input-beats
    static SslContext doBuild(final SslContextBuilder builder) throws Exception {
        try {
            return builder.build();
        } catch (SSLException e) {
            LOGGER.debug("Failed to initialize SSL", e);
            // unwrap generic wrapped exception from Netty's JdkSsl{Client|Server}Context
            if ("failed to initialize the server-side SSL context".equals(e.getMessage()) ||
                "failed to initialize the client-side SSL context".equals(e.getMessage())) {
                // Netty catches Exception and simply wraps: throw new SSLException("...", e);
                if (e.getCause() instanceof Exception) throw (Exception) e.getCause();
            }
            throw e;
        } catch (Exception e) {
            LOGGER.debug("Failed to initialize SSL", e);
            throw e;
        }
    }

    public static String[] getDefaultCiphers() {
        if (isUnlimitedJCEAvailable()){
            return DEFAULT_CIPHERS;
        } else {
            LOGGER.warn("JCE Unlimited Strength Jurisdiction Policy not installed - max key length is 128 bits");
            return DEFAULT_CIPHERS_LIMITED;
        }
    }

    public static boolean isUnlimitedJCEAvailable(){
        try {
            return (Cipher.getMaxAllowedKeyLength("AES") > 128);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.warn("AES not available", e);
            return false;
        }
    }

    /**
     * It's a Builder.
     * It's a Factory.
     * It's a Factory that makes a {@code SslContextBuilder}.
     *
     * <p> A {@code ServerSslContextBuilderFactory} is capable of instantiating
     * a server-type {@code SslContextBuilder} that will present an identity to clients.
     *
     * <p>This abstraction allows us to bridge the gap between identity-related information being required to
     * initialize an {@code SslContextBuilder}, and our {@code SslSimpleBuilder}'s behaviour of delaying
     * initialization of its {@code SslContextBuilder} until {@link SslSimpleBuilder#build()}.</p>
     *
     * <p>Its implementations are:
     *
     * <ul>
     *     <li>{@link FromKeyStore} - see {@link SslSimpleBuilder#serverFromKeystore(String, String)}</li>
     *     <li>{@link FromCertificateKeyPair} - see {@link SslSimpleBuilder#serverFromCertificate(String, String, String)}</li>
     * </ul>
     */
    private interface ServerSslContextBuilderFactory {
        SslContextBuilder init() throws Exception;

        /**
         * This {@code ServerSslContextBuilderFactory.FromKeyStore} is capable of creating
         * an {@code SslContextBuilder} for a server using a keystore-on-disk as an identity provider.
         */
        class FromKeyStore implements ServerSslContextBuilderFactory {
            private final String keyStorePath;
            private final char[] keyStorePassword;

            public FromKeyStore(final String keyStorePath, final String keyStorePassword) {
                this.keyStorePath = keyStorePath;
                this.keyStorePassword = keyStorePassword.toCharArray();
            }

            private KeyManagerFactory getKeyManagerFactory() throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
                final KeyStore keyStore = KeystoreUtil.load(keyStorePath, keyStorePassword);

                final String algorithm = KeyManagerFactory.getDefaultAlgorithm();
                final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(algorithm);

                keyManagerFactory.init(keyStore, keyStorePassword);

                return keyManagerFactory;
            }

            @Override
            public SslContextBuilder init() throws Exception {
                LOGGER.debug("Creating SslContextBuilder for server with keystore from `{}`", keyStorePath);

                final KeyManagerFactory keyManagerFactory = getKeyManagerFactory();

                return SslContextBuilder.forServer(keyManagerFactory);
            }
        }

        /**
         * This {@code ServerSslContextBuilderFactory.FromCertificateKeyPair} is capable of creating
         * an {@code SslContextBuilder} for a server using a certificate-key-pair-on-disk as an identity provider.
         */
        class FromCertificateKeyPair implements ServerSslContextBuilderFactory {
            private final String certificatePath;
            private final String keyPath;
            private final String keyPassphrase;

            public FromCertificateKeyPair(final String certificatePath,
                                          final String keyPath,
                                          final String keyPassphrase) {
                this.certificatePath = certificatePath;
                this.keyPath = keyPath;
                this.keyPassphrase = keyPassphrase;
            }

            @Override
            public SslContextBuilder init() throws Exception {
                LOGGER.debug("Creating SslContextBuilder for server with certificate from `{}` and key from `{}`", certificatePath, keyPath);

                final File certificateFile = new File(certificatePath);
                final File keyFile = new File(keyPath);

                return SslContextBuilder.forServer(certificateFile, keyFile, keyPassphrase);
            }
        }
    }

    /**
     * An {@code SslContextBuilderTrustConfigurator} is capable of configuring
     * a {@code SslContextBuilder} with a trust manager, mutating it to override
     * its Trust Manager.
     *
     * <p>It has one implementation:
     *
     * <ul>
     *     <li>{@link FromCertificateAuthorities} - see {@link SslSimpleBuilder#setCertificateAuthorities(String[])}</li>
     * </ul>
     */
    @FunctionalInterface
    interface SslContextBuilderTrustConfigurator {
        SslContextBuilder apply(final SslContextBuilder sslContextBuilder) throws Exception;


        /**
         * This {@code SslContextBuilderTrustConfigurator.FromCertificateAuthorities} is capable of configuring
         * the trust material of an {@code SslContextBuilder} using zero or more certificate-authorities on disk.
         */
        class FromCertificateAuthorities implements SslContextBuilderTrustConfigurator {
            private final List<String> certificateAuthoritiesPaths;

            private static final X509Certificate[] ZERO_LENGTH_X509_CERTIFICATES_ARRAY = new X509Certificate[0];

            public FromCertificateAuthorities(final String[] certificateAuthoritiesPaths) {
                this.certificateAuthoritiesPaths = Collections.unmodifiableList(Arrays.asList(certificateAuthoritiesPaths));
            }

            @Override
            public SslContextBuilder apply(SslContextBuilder sslContextBuilder) throws Exception {
                LOGGER.debug("Configuring trust with certificate authorities {}", certificateAuthoritiesPaths);
                return sslContextBuilder.trustManager(loadCertificateCollection());
            }

            private X509Certificate[] loadCertificateCollection() throws IOException, CertificateException {
                LOGGER.debug("Load certificates collection");
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

                List<X509Certificate> collections = new ArrayList<X509Certificate>();

                for (String certificate : this.certificateAuthoritiesPaths) {
                    LOGGER.debug("Loading certificates from file `{}`", certificate);

                    try(InputStream in = Files.newInputStream(Paths.get(certificate))) {
                        @SuppressWarnings("unchecked") // X.509-type CertificateFactory#generateCertificates always returns List<X509Certificate>
                        List<X509Certificate> certificatesChains = (List<X509Certificate>) certificateFactory.generateCertificates(in);
                        collections.addAll(certificatesChains);
                    }
                }

                return collections.toArray(ZERO_LENGTH_X509_CERTIFICATES_ARRAY);
            }
        }
    }
    static class KeystoreUtil {
        private static String guessKeystoreType(final String path) {
            if (path.endsWith(".jks")) { return "jks"; }
            if (path.endsWith(".p12")) { return "p12"; }

            return KeyStore.getDefaultType();
        }

        public static KeyStore load(final String keyStorePath, final char[] keyStorePassword) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
            final String keystoreType = guessKeystoreType(keyStorePath);
            final KeyStore keyStore = KeyStore.getInstance(keystoreType);

            LOGGER.debug("Loading {}-type Keystore from file `{}`", keystoreType, keyStorePath);
            keyStore.load(Files.newInputStream(Paths.get(keyStorePath)), keyStorePassword);

            return keyStore;
        }
    }
}
