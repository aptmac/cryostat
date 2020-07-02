/*-
 * #%L
 * Container JFR
 * %%
 * Copyright (C) 2020 Red Hat, Inc.
 * %%
 * The Universal Permissive License (UPL), Version 1.0
 *
 * Subject to the condition set forth below, permission is hereby granted to any
 * person obtaining a copy of this software, associated documentation and/or data
 * (collectively the "Software"), free of charge and under any and all copyright
 * rights in the Software, and any and all patent rights owned or freely
 * licensable by each licensor hereunder covering either (i) the unmodified
 * Software as contributed to or provided by such licensor, or (ii) the Larger
 * Works (as defined below), to deal in both
 *
 * (a) the Software, and
 * (b) any piece of software and/or hardware listed in the lrgrwrks.txt file if
 * one is included with the Software (each a "Larger Work" to which the Software
 * is contributed by such licensors),
 *
 * without restriction, including without limitation the rights to copy, create
 * derivative works of, display, perform, and distribute the Software and make,
 * use, sell, offer for sale, import, export, have made, and have sold the
 * Software and the Larger Work(s), and to sublicense the foregoing rights on
 * either these or other terms.
 *
 * This license is subject to the following condition:
 * The above copyright notice and either this complete permission notice or at
 * a minimum a reference to the UPL must be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * #L%
 */
package com.redhat.rhjmc.containerjfr.net.web.handlers;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CompletableFuture;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import org.openjdk.jmc.rjmx.services.jfr.IFlightRecorderService;
import org.openjdk.jmc.rjmx.services.jfr.IRecordingDescriptor;

import com.redhat.rhjmc.containerjfr.core.log.Logger;
import com.redhat.rhjmc.containerjfr.core.net.JFRConnection;
import com.redhat.rhjmc.containerjfr.core.sys.Environment;
import com.redhat.rhjmc.containerjfr.net.AuthManager;
import com.redhat.rhjmc.containerjfr.net.TargetConnectionManager;
import com.redhat.rhjmc.containerjfr.net.web.HttpMimeType;

import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.impl.HttpStatusException;

@ExtendWith(MockitoExtension.class)
class TargetRecordingGetHandlerTest {

    TargetRecordingGetHandler handler;
    @Mock AuthManager authManager;
    @Mock Environment env;
    @Mock TargetConnectionManager targetConnectionManager;
    @Mock Logger logger;
    @Mock JFRConnection connection;
    @Mock IFlightRecorderService service;

    @BeforeEach
    void setup() {
        this.handler =
                new TargetRecordingGetHandler(authManager, env, targetConnectionManager, logger);
    }

    @Test
    void shouldHandleGETRequest() {
        MatcherAssert.assertThat(handler.httpMethod(), Matchers.equalTo(HttpMethod.GET));
    }

    @Test
    void shouldHandleCorrectPath() {
        MatcherAssert.assertThat(
                handler.path(),
                Matchers.equalTo("/api/v1/targets/:targetId/recordings/:recordingName"));
    }

    @Test
    void shouldNotBeAsync() {
        Assertions.assertFalse(handler.isAsync());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false}) // FIXME low memory pressure streaming test hangs
    void shouldHandleRecordingDownloadRequest(boolean lowMemPressure) throws Exception {
        when(env.hasEnv(TargetRecordingGetHandler.USE_LOW_MEM_PRESSURE_STREAMING_ENV))
                .thenReturn(lowMemPressure);

        when(authManager.validateHttpHeader(Mockito.any()))
                .thenReturn(CompletableFuture.completedFuture(true));

        when(connection.getService()).thenReturn(service);
        RoutingContext ctx = mock(RoutingContext.class);
        HttpServerResponse resp = mock(HttpServerResponse.class);
        when(ctx.response()).thenReturn(resp);
        HttpServerRequest req = mock(HttpServerRequest.class);
        when(ctx.request()).thenReturn(req);

        byte[] src = new byte[1024 * 1024];
        new Random(123456).nextBytes(src);
        IRecordingDescriptor descriptor = mock(IRecordingDescriptor.class);
        String recordingName = "foo";
        when(descriptor.getName()).thenReturn(recordingName);
        when(service.openStream(descriptor, false)).thenReturn(new ByteArrayInputStream(src));
        when(service.getAvailableRecordings()).thenReturn(List.of(descriptor));

        Buffer dst = Buffer.buffer(1024 * 1024);
        when(resp.write(Mockito.any(Buffer.class)))
                .thenAnswer(
                        invocation -> {
                            Buffer chunk = invocation.getArgument(0);
                            dst.appendBuffer(chunk);
                            return null;
                        });
        when(ctx.pathParam("targetId")).thenReturn("fooHost:0");
        when(ctx.pathParam("recordingName")).thenReturn(recordingName);

        when(targetConnectionManager.connect(Mockito.anyString())).thenReturn(connection);

        handler.handle(ctx);

        verify(resp).putHeader(HttpHeaders.CONTENT_TYPE, HttpMimeType.OCTET_STREAM.mime());
        Assertions.assertArrayEquals(src, dst.getBytes());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false}) // FIXME low memory pressure streaming test hangs
    void shouldHandleRecordingDownloadRequestWithJfrSuffix(boolean lowMemPressure)
            throws Exception {
        when(env.hasEnv(TargetRecordingGetHandler.USE_LOW_MEM_PRESSURE_STREAMING_ENV))
                .thenReturn(lowMemPressure);

        when(authManager.validateHttpHeader(Mockito.any()))
                .thenReturn(CompletableFuture.completedFuture(true));

        when(connection.getService()).thenReturn(service);
        RoutingContext ctx = mock(RoutingContext.class);
        HttpServerResponse resp = mock(HttpServerResponse.class);
        when(ctx.response()).thenReturn(resp);
        HttpServerRequest req = mock(HttpServerRequest.class);
        when(ctx.request()).thenReturn(req);

        byte[] src = new byte[1024 * 1024];
        new Random(123456).nextBytes(src);
        IRecordingDescriptor descriptor = mock(IRecordingDescriptor.class);
        String recordingName = "foo";
        when(descriptor.getName()).thenReturn(recordingName);
        when(service.openStream(descriptor, false)).thenReturn(new ByteArrayInputStream(src));
        when(service.getAvailableRecordings()).thenReturn(List.of(descriptor));

        Buffer dst = Buffer.buffer(1024 * 1024);
        when(resp.write(Mockito.any(Buffer.class)))
                .thenAnswer(
                        invocation -> {
                            Buffer chunk = invocation.getArgument(0);
                            dst.appendBuffer(chunk);
                            return null;
                        });
        when(ctx.pathParam("targetId")).thenReturn("fooHost:0");
        when(ctx.pathParam("recordingName")).thenReturn(recordingName + ".jfr");

        when(targetConnectionManager.connect(Mockito.anyString())).thenReturn(connection);

        handler.handle(ctx);

        verify(resp).putHeader(HttpHeaders.CONTENT_TYPE, "application/octet-stream");
        Assertions.assertArrayEquals(src, dst.getBytes());
    }

    @Test
    void shouldRespond404IfRecordingNameNotFound() throws Exception {
        when(authManager.validateHttpHeader(Mockito.any()))
                .thenReturn(CompletableFuture.completedFuture(true));

        RoutingContext ctx = mock(RoutingContext.class);
        HttpServerRequest req = mock(HttpServerRequest.class);
        when(ctx.request()).thenReturn(req);

        when(targetConnectionManager.connect(Mockito.anyString())).thenReturn(connection);
        when(connection.getService()).thenReturn(service);
        when(service.getAvailableRecordings()).thenReturn(List.of());

        when(ctx.pathParam("targetId")).thenReturn("fooHost:0");
        when(ctx.pathParam("recordingName")).thenReturn("someRecording");

        HttpStatusException ex =
                Assertions.assertThrows(HttpStatusException.class, () -> handler.handle(ctx));
        ex.printStackTrace();
        MatcherAssert.assertThat(ex.getStatusCode(), Matchers.equalTo(404));
    }

    @Test
    void shouldResponse500IfUnexpectedExceptionThrown() throws Exception {
        when(authManager.validateHttpHeader(Mockito.any()))
                .thenReturn(CompletableFuture.completedFuture(true));

        RoutingContext ctx = mock(RoutingContext.class);
        HttpServerRequest req = mock(HttpServerRequest.class);
        when(ctx.request()).thenReturn(req);

        when(targetConnectionManager.connect(Mockito.anyString())).thenReturn(connection);
        when(connection.getService()).thenReturn(service);
        when(service.getAvailableRecordings()).thenThrow(NullPointerException.class);

        when(ctx.pathParam("targetId")).thenReturn("fooHost:0");
        when(ctx.pathParam("recordingName")).thenReturn("someRecording");

        HttpStatusException ex =
                Assertions.assertThrows(HttpStatusException.class, () -> handler.handle(ctx));
        ex.printStackTrace();
        MatcherAssert.assertThat(ex.getStatusCode(), Matchers.equalTo(500));
    }
}