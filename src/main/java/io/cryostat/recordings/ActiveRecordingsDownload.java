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
package io.cryostat.recordings;

import java.io.InputStream;

import io.cryostat.Producers;
import io.cryostat.recordings.DownloadTokenService.TokenInfo;
import io.cryostat.security.UserInfoResolver;
import io.cryostat.util.HttpMimeType;

import io.smallrye.common.annotation.Blocking;
import io.smallrye.common.annotation.Identifier;
import io.vertx.ext.web.RoutingContext;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.SecurityContext;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.RestPath;
import org.jboss.resteasy.reactive.RestQuery;
import org.jboss.resteasy.reactive.RestResponse;
import org.jboss.resteasy.reactive.RestResponse.ResponseBuilder;

@Path("/api/v4/activedownload/{id}")
public class ActiveRecordingsDownload {

    @Inject RecordingHelper recordingHelper;
    @Inject DownloadTokenService tokenService;
    @Inject Logger logger;

    @Inject
    @Identifier(Producers.BASE64_URL)
    Base64 base64Url;

    @POST
    @Path("/token")
    @RolesAllowed("read")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Generate a download token for an active recording",
            description =
                    """
                    Generate a one-time download token for an active recording. This token can be used by external
                    applications (like JDK Mission Control) to download the recording without requiring browser
                    cookies or session authentication. The token expires after a configured duration (default 10
                    minutes) and can only be used once.
                    """)
    public TokenResponse generateActiveRecordingToken(
            @Parameter(required = true, description = "The ID of the active recording") @RestPath
                    long id,
            @Context SecurityContext securityContext,
            @Context RoutingContext routingContext) {

        // Verify the recording exists
        ActiveRecording recording = ActiveRecording.find("id", id).firstResult();
        if (recording == null) {
            throw new NotFoundException("Active recording not found");
        }

        String username = UserInfoResolver.resolveUsername(securityContext, routingContext);
        TokenInfo tokenInfo = tokenService.generateToken(id, "active", username);

        // Build the download URL with the token - use localhost since port is exposed to host
        // External applications like JMC will connect directly to the backend with the token
        String backendPort = System.getenv().getOrDefault("QUARKUS_HTTP_PORT", "8181");
        String downloadUrl =
                String.format(
                        "http://localhost:%s/api/v4/activedownload/%d?token=%s",
                        backendPort, id, tokenInfo.token());

        logger.infov(
                "Generated download token for active recording {0} for user {1}, URL: {2}",
                id, username, downloadUrl);

        return new TokenResponse(tokenInfo.token(), downloadUrl, tokenInfo.expiresAt());
    }

    @GET
    @Blocking
    @PermitAll
    @Operation(
            summary = "Download a Flight Recording binary file",
            description =
                    """
                    Given a recording ID and a remote recording ID within that target, Cryostat will open a remote
                    connection to the target and pipe back a data stream containing the Flight Recording binary file
                    format for that recording. The client can feed this data to other tooling which ingests the JFR
                    binary file format.

                    Authentication can be provided either via standard session authentication (cookies) or via a
                    one-time download token passed as a query parameter. Download tokens can be generated via the
                    /api/v4/activedownload/{id}/token endpoint.
                    """)
    public RestResponse<InputStream> handleActiveDownload(
            @RestPath long id,
            @Parameter(
                            required = false,
                            description =
                                    "One-time download token for authentication (alternative to"
                                            + " session cookies)")
                    @RestQuery
                    String token,
            @Context SecurityContext securityContext)
            throws Exception {

        // Check authentication: either valid session or valid token
        if (StringUtils.isNotBlank(token)) {
            // Token-based authentication
            try {
                tokenService.validateAndConsumeToken(token, id, "active");
                logger.debugv("Token authentication successful for active recording {0}", id);
            } catch (ForbiddenException e) {
                logger.warnv(
                        "Token authentication failed for active recording {0}: {1}",
                        id, e.getMessage());
                throw e;
            }
        } else {
            // Session-based authentication - check if user has required role
            if (securityContext.getUserPrincipal() == null
                    || !securityContext.isUserInRole("read")) {
                logger.warnv(
                        "Unauthorized access attempt to active recording {0} without valid token or"
                                + " session",
                        id);
                throw new ForbiddenException(
                        "Authentication required. Provide a valid session or download token.");
            }
        }

        ActiveRecording recording = ActiveRecording.find("id", id).singleResult();
        return ResponseBuilder.<InputStream>ok()
                .header(
                        HttpHeaders.CONTENT_DISPOSITION,
                        String.format("attachment; filename=\"%s.jfr\"", recording.name))
                .header(HttpHeaders.CONTENT_TYPE, HttpMimeType.OCTET_STREAM.mime())
                .entity(recordingHelper.getActiveInputStream(recording))
                .build();
    }

    public static record TokenResponse(String token, String downloadUrl, long expiresAt) {}
}
