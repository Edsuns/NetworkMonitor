package io.github.edsuns.net;

import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.net.ssl.*;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Created by Edsuns@qq.com on 2021/9/4.
 */
@ParametersAreNonnullByDefault
public class NetworkMonitor {

    public static class ProbeResult {
        public static final int SUCCESS_CODE = HttpURLConnection.HTTP_NO_CONTENT;
        public static final int FAILED_CODE = 599;

        static final ProbeResult FAILED = new ProbeResult(FAILED_CODE);

        public final int httpResponseCode;
        @Nullable
        public final String redirectUrl;
        @Nullable
        public final String originUrl;

        ProbeResult(int httpResponseCode) {
            this(httpResponseCode, null, null);
        }

        ProbeResult(int httpResponseCode, @Nullable String redirectUrl, @Nullable String originUrl) {
            this.httpResponseCode = httpResponseCode;
            this.redirectUrl = redirectUrl;
            this.originUrl = originUrl;
        }

        public boolean isSuccessful() {
            return httpResponseCode == SUCCESS_CODE;
        }

        public boolean isPortal() {
            return !isSuccessful() && (httpResponseCode >= 200) && (httpResponseCode <= 399);
        }

        public boolean isFailed() {
            return !isSuccessful() && !isPortal();
        }

        @Override
        public String toString() {
            return "ProbeResult{" +
                    "httpResponseCode=" + httpResponseCode +
                    ", redirectUrl='" + redirectUrl + '\'' +
                    ", originUrl='" + originUrl + '\'' +
                    '}';
        }
    }

    static final HostnameVerifier trustAllHostnameVerifier = (hostname, session) -> true;
    static final SSLSocketFactory trustAllSSLFactory;

    static {
        final TrustManager[] trustAllCerts = {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    }
                }
        };
        try {
            final SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, null);
            trustAllSSLFactory = sc.getSocketFactory();
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException("Failed to load SSLSocketFactory in NetworkMonitor", e);
        }
    }

    private static final String DEFAULT_HTTPS_URL = "https://fonts.googleapis.com/generate_204";
    private static final String DEFAULT_HTTP_URL = "http://connectivitycheck.gstatic.com/generate_204";
    private static final String DEFAULT_FALLBACK_HTTPS_URL = "https://g.cn/generate_204";
    private static final String DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) "
            + "AppleWebKit/537.36 (KHTML, like Gecko) "
            + "Chrome/60.0.3112.32 Safari/537.36";

    private static final int SOCKET_TIMEOUT_MS = 10000;
    private static final int PROBE_TIMEOUT_MS = 3000;

    private final URL probeHttpUrl;
    private final URL probeHttpsUrl;
    private final URL fallbackHttpsUrl;

    public NetworkMonitor() {
        this(DEFAULT_HTTP_URL, DEFAULT_HTTPS_URL);
    }

    public NetworkMonitor(String probeHttpUrl, String probeHttpsUrl) {
        if (!probeHttpUrl.startsWith("http:") || !probeHttpsUrl.startsWith("https:")) {
            throw new IllegalArgumentException("Wrong protocol of the url!");
        }
        try {
            this.probeHttpUrl = new URL(probeHttpUrl);
            this.probeHttpsUrl = new URL(probeHttpsUrl);
            this.fallbackHttpsUrl = new URL(DEFAULT_FALLBACK_HTTPS_URL);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    public ProbeResult sendProbe() {
        // Number of probes to wait for. If a probe completes with a conclusive answer
        // it shortcuts the latch immediately by forcing the count to 0.
        final CountDownLatch latch = new CountDownLatch(2);
        final class ProbeThread extends Thread {
            private final boolean mIsHttps;
            private volatile ProbeResult mResult = ProbeResult.FAILED;

            public ProbeThread(boolean isHttps) {
                mIsHttps = isHttps;
            }

            public ProbeResult result() {
                return mResult;
            }

            @Override
            public void run() {
                if (mIsHttps) {
                    mResult = sendHttpProbe(probeHttpsUrl, true);
                } else {
                    mResult = sendHttpProbe(probeHttpUrl, false);
                }
                if (mResult.isPortal() || mResult.isSuccessful()) {
                    // Stop waiting immediately if https succeeds or if http finds a portal.
                    while (latch.getCount() > 0) {
                        latch.countDown();
                    }
                }
                // Signal this probe has completed.
                latch.countDown();
            }
        }
        final ProbeThread httpsProbe = new ProbeThread(true);
        final ProbeThread httpProbe = new ProbeThread(false);
        try {
            httpsProbe.start();
            httpProbe.start();
            latch.await(PROBE_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            return ProbeResult.FAILED;
        }
        final ProbeResult httpResult = httpProbe.result();
        final ProbeResult httpsResult = httpsProbe.result();
        // Look for a conclusive probe result first.
        if (httpResult.isPortal() || httpResult.isSuccessful()) {
            return httpResult;
        }
        if (httpsResult.isPortal() || httpsResult.isSuccessful()) {
            return httpsResult;
        }
        // Use a fallback probe to try again portal detection.
        ProbeResult result = sendHttpProbe(fallbackHttpsUrl, true);
        if (result.isPortal() || result.isSuccessful()) {
            return result;
        }
        // Otherwise, wait until https probe completes and use its result.
        try {
            httpsProbe.join();
            return httpsProbe.result();
        } catch (InterruptedException e) {
            return ProbeResult.FAILED;
        }
    }

    private ProbeResult sendHttpProbe(URL url, boolean isHttps) {
        HttpURLConnection connection = null;
        int httpResponseCode = ProbeResult.FAILED_CODE;
        String redirectUrl = null;
        try {
            connection = (HttpURLConnection) url.openConnection();
            connection.setInstanceFollowRedirects(false);
            connection.setConnectTimeout(SOCKET_TIMEOUT_MS);
            connection.setReadTimeout(SOCKET_TIMEOUT_MS);
            connection.setUseCaches(false);
            connection.setRequestProperty("User-Agent", DEFAULT_USER_AGENT);

            if (isHttps) {
                HttpsURLConnection https = (HttpsURLConnection) connection;
                // Trust all certs including captive portal's in order to obtain the sign-in URL.
                // Otherwise, the connection will be terminated due to untrusted certificate from captive portal.
                https.setHostnameVerifier(trustAllHostnameVerifier);
                https.setSSLSocketFactory(trustAllSSLFactory);
            }

            httpResponseCode = connection.getResponseCode();
            redirectUrl = connection.getHeaderField("location");

            // If it is considered a captive portal (i.e. can't browse a 204), a different sign-in URL is needed.
            // This could be the result of an HTTP proxy server.
            if (httpResponseCode == 200) {
                if (connection.getContentLengthLong() == 0) {
                    // Consider 200 response with "Content-length=0" to not be a captive portal.
                    httpResponseCode = ProbeResult.SUCCESS_CODE;
                } else if (connection.getContentLengthLong() == -1) {
                    // When no Content-length (default value == -1), attempt to read a byte from the
                    // response. Do not use available() as it is unreliable.
                    if (connection.getInputStream().read() == -1) {
                        httpResponseCode = ProbeResult.SUCCESS_CODE;
                    }
                }
            }
        } catch (IOException ignored) {
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
        return new ProbeResult(httpResponseCode, redirectUrl, url.toString());
    }
}
