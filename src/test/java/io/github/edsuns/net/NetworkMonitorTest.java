package io.github.edsuns.net;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Created by Edsuns@qq.com on 2021/9/4.
 */
public class NetworkMonitorTest {
    @Test
    public void probeSuccessful() {
        final NetworkMonitor.ProbeResult result = new NetworkMonitor().sendProbe();
        System.out.println(result);
        assertTrue(result.isSuccessful());
    }

    @Test
    public void probeFallbackSuccessfulWhenFailed() {
        final NetworkMonitor.ProbeResult failedResult =
                new NetworkMonitor("http://google.cn/404", "https://google.cn/404").sendProbe();
        System.out.println(failedResult);
        assertTrue(failedResult.isSuccessful());
    }

    @Test
    public void probeFallbackSuccessfulWhenTimeout() {
        final NetworkMonitor.ProbeResult timeoutResult =
                new NetworkMonitor("http://localhost", "https://localhost").sendProbe();
        System.out.println(timeoutResult);
        assertTrue(timeoutResult.isSuccessful());
    }
}
