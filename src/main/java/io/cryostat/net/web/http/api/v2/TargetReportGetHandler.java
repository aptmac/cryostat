/*
 * Copyright The Cryostat Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.cryostat.net.web.http.api.v2;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import javax.inject.Inject;
import javax.inject.Named;

import io.cryostat.configuration.CredentialsManager;
import io.cryostat.net.AuthManager;
import io.cryostat.net.reports.ReportService;
import io.cryostat.net.reports.ReportsModule;
import io.cryostat.net.reports.SubprocessReportGenerator;
import io.cryostat.net.security.ResourceAction;
import io.cryostat.net.security.jwt.AssetJwtHelper;
import io.cryostat.net.web.WebServer;
import io.cryostat.net.web.http.HttpMimeType;
import io.cryostat.net.web.http.api.ApiVersion;
import io.cryostat.recordings.RecordingNotFoundException;

import com.nimbusds.jwt.JWT;
import dagger.Lazy;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.RoutingContext;
import org.apache.commons.lang3.exception.ExceptionUtils;

class TargetReportGetHandler extends AbstractAssetJwtConsumingHandler {

    protected final ReportService reportService;
    protected final long reportGenerationTimeoutSeconds;

    @Inject
    TargetReportGetHandler(
            AuthManager auth,
            CredentialsManager credentialsManager,
            AssetJwtHelper jwtFactory,
            Lazy<WebServer> webServer,
            ReportService reportService,
            @Named(ReportsModule.REPORT_GENERATION_TIMEOUT_SECONDS)
                    long reportGenerationTimeoutSeconds) {
        super(auth, credentialsManager, jwtFactory, webServer);
        this.reportService = reportService;
        this.reportGenerationTimeoutSeconds = reportGenerationTimeoutSeconds;
    }

    @Override
    public ApiVersion apiVersion() {
        return ApiVersion.V2_1;
    }

    @Override
    public HttpMethod httpMethod() {
        return HttpMethod.GET;
    }

    @Override
    public String path() {
        return basePath() + "targets/:targetId/reports/:recordingName";
    }

    @Override
    public Set<ResourceAction> resourceActions() {
        return EnumSet.of(
                ResourceAction.READ_TARGET,
                ResourceAction.READ_RECORDING,
                ResourceAction.CREATE_REPORT,
                ResourceAction.READ_REPORT);
    }

    @Override
    public List<HttpMimeType> produces() {
        return List.of(HttpMimeType.JSON);
    }

    @Override
    public boolean isAsync() {
        return false;
    }

    @Override
    public boolean isOrdered() {
        return true;
    }

    @Override
    public void handleWithValidJwt(RoutingContext ctx, JWT jwt) throws Exception {
        String recordingName = ctx.pathParam("recordingName");
        List<String> queriedFilter = ctx.queryParam("filter");
        String rawFilter = queriedFilter.isEmpty() ? "" : queriedFilter.get(0);
        try {
            ctx.response()
                    .putHeader(HttpHeaders.CONTENT_TYPE, ctx.getAcceptableContentType())
                    .putHeader(HttpHeaders.CONTENT_DISPOSITION, "inline")
                    .end(
                            reportService
                                    .get(
                                            getConnectionDescriptorFromJwt(ctx, jwt),
                                            recordingName,
                                            rawFilter)
                                    .get(reportGenerationTimeoutSeconds, TimeUnit.SECONDS));
        } catch (CompletionException | ExecutionException ee) {

            Exception rootCause = (Exception) ExceptionUtils.getRootCause(ee);

            if (targetRecordingNotFound(rootCause)) {
                throw new ApiException(404, ee);
            }
            throw ee;
        }
    }

    // TODO this needs to also handle the case where sidecar report generator container responds 404
    private boolean targetRecordingNotFound(Exception rootCause) {
        if (rootCause instanceof RecordingNotFoundException) {
            return true;
        }
        boolean isReportGenerationException =
                rootCause instanceof SubprocessReportGenerator.SubprocessReportGenerationException;
        if (!isReportGenerationException) {
            return false;
        }
        SubprocessReportGenerator.SubprocessReportGenerationException generationException =
                (SubprocessReportGenerator.SubprocessReportGenerationException) rootCause;
        boolean isTargetConnectionFailure =
                generationException.getStatus()
                        == SubprocessReportGenerator.ExitStatus.TARGET_CONNECTION_FAILURE;
        boolean isNoSuchRecording =
                generationException.getStatus()
                        == SubprocessReportGenerator.ExitStatus.NO_SUCH_RECORDING;
        return isTargetConnectionFailure || isNoSuchRecording;
    }
}
