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
package io.cryostat.analysis;

import java.io.IOException;

import org.openjdk.jmc.common.IDisplayable;
import org.openjdk.jmc.common.item.IItemCollection;
import org.openjdk.jmc.flightrecorder.CouldNotLoadRecordingException;
import org.openjdk.jmc.flightrecorder.JfrLoaderToolkit;
import org.openjdk.jmc.flightrecorder.jdk.JdkAggregators;
import org.openjdk.jmc.flightrecorder.serializers.json.IItemCollectionJsonSerializer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.cryostat.recordings.RecordingHelper;

import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import org.jboss.resteasy.reactive.RestPath;

@Path("/api/beta/analysis/{jvmId}/{recordingName}")
public class AnalysisToolkit {

    @Inject RecordingHelper recordingHelper;

    @GET
    @Path("/events")
    @RolesAllowed("read")
    public String getEvents(@RestPath String jvmId, @RestPath String recordingName)
            throws IOException, CouldNotLoadRecordingException {
        IItemCollection items = getItemsFromArchivedInputStream(jvmId, recordingName);
        return IItemCollectionJsonSerializer.toJsonString(items);
    }

    @GET
    @Path("/jvm-internals")
    @RolesAllowed("read")
    public String getJvmInternalsInfo(@RestPath String jvmId, @RestPath String recordingName)
            throws IOException, CouldNotLoadRecordingException {
        IItemCollection items = getItemsFromArchivedInputStream(jvmId, recordingName);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode rootNode = mapper.createObjectNode();

        ObjectNode jvmInternalsNode = mapper.createObjectNode();
        jvmInternalsNode.put("JVM_START_TIME", items.getAggregate(JdkAggregators.JVM_START_TIME).displayUsing(IDisplayable.AUTO));
        jvmInternalsNode.put("JVM_NAME", items.getAggregate(JdkAggregators.JVM_NAME));
        jvmInternalsNode.put("PID", items.getAggregate(JdkAggregators.PID));
        jvmInternalsNode.put("JVM_VERSION", items.getAggregate(JdkAggregators.JVM_VERSION));
        jvmInternalsNode.put("JVM_ARGUMENTS", items.getAggregate(JdkAggregators.JVM_ARGUMENTS));
        jvmInternalsNode.put("JAVA_ARGUMENTS", items.getAggregate(JdkAggregators.JAVA_ARGUMENTS));
        if (items.getAggregate(JdkAggregators.JVM_SHUTDOWN_TIME) != null) {
            jvmInternalsNode.put("JVM_SHUTDOWN_TIME", items.getAggregate(JdkAggregators.JVM_SHUTDOWN_TIME).longValue());
        }
        if (items.getAggregate(JdkAggregators.JVM_SHUTDOWN_REASON) != null) {
            jvmInternalsNode.put("JVM_SHUTDOWN_REASON", items.getAggregate(JdkAggregators.JVM_SHUTDOWN_REASON));
        }
        rootNode.set("JVM_INTERNALS", jvmInternalsNode);

        // TODO: use a filter to fetch the JVM Flags and Logs
        return mapper.writeValueAsString(rootNode);
    }

    // Note: in JMC this is the "SystemPage"
    @GET
    @Path("/environment")
    @RolesAllowed("read")
    public String getEnvironmentInfo(@RestPath String jvmId, @RestPath String recordingName)
            throws IOException, CouldNotLoadRecordingException {
        IItemCollection items = getItemsFromArchivedInputStream(jvmId, recordingName);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode rootNode = mapper.createObjectNode();
        ObjectNode environmentNode = mapper.createObjectNode();
        environmentNode.put("CPU_TYPE", items.getAggregate(JdkAggregators.CPU_TYPE));
        environmentNode.put("MIN_NUMBER_OF_CORES", items.getAggregate(JdkAggregators.MIN_NUMBER_OF_CORES).displayUsing(IDisplayable.AUTO));
        environmentNode.put("MIN_HW_THREADS", items.getAggregate(JdkAggregators.MIN_HW_THREADS).displayUsing(IDisplayable.AUTO));
        environmentNode.put("MIN_NUMBER_OF_SOCKETS", items.getAggregate(JdkAggregators.MIN_NUMBER_OF_SOCKETS).displayUsing(IDisplayable.AUTO));
        environmentNode.put("CPU_DESCRIPTION", items.getAggregate(JdkAggregators.CPU_DESCRIPTION));
        environmentNode.put("MIN_TOTAL_MEMORY", items.getAggregate(JdkAggregators.MIN_TOTAL_MEMORY).displayUsing(IDisplayable.AUTO));
        environmentNode.put("OS_VERSION", items.getAggregate(JdkAggregators.OS_VERSION));
        rootNode.set("ENVIRONMENT", environmentNode);
        return mapper.writeValueAsString(rootNode);
    }

    @GET
    @Path("/gc")
    @RolesAllowed("read")
    public String getGarbageCollectionInfo(@RestPath String jvmId, @RestPath String recordingName)
            throws IOException, CouldNotLoadRecordingException {
        IItemCollection items = getItemsFromArchivedInputStream(jvmId, recordingName);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode rootNode = mapper.createObjectNode();
        ObjectNode gcConfigurationNode = mapper.createObjectNode();

        ObjectNode gcConfigSection = mapper.createObjectNode();
        gcConfigSection.put("YOUNG_COLLECTOR", items.getAggregate(JdkAggregators.YOUNG_COLLECTOR));
        gcConfigSection.put("OLD_COLLECTOR", items.getAggregate(JdkAggregators.OLD_COLLECTOR));
        gcConfigSection.put("CONCURRENT_GC_THREAD_COUNT_MIN", items.getAggregate(JdkAggregators.CONCURRENT_GC_THREAD_COUNT_MIN).displayUsing(IDisplayable.AUTO));
        gcConfigSection.put("PARALLEL_GC_THREAD_COUNT_MIN", items.getAggregate(JdkAggregators.PARALLEL_GC_THREAD_COUNT_MIN).displayUsing(IDisplayable.AUTO));
        gcConfigSection.put("EXPLICIT_GC_CONCURRENT", items.getAggregate(JdkAggregators.EXPLICIT_GC_CONCURRENT).toString());
        gcConfigSection.put("EXPLICIT_GC_DISABLED", items.getAggregate(JdkAggregators.EXPLICIT_GC_DISABLED).toString());
        gcConfigSection.put("USE_DYNAMIC_GC_THREADS", items.getAggregate(JdkAggregators.USE_DYNAMIC_GC_THREADS).toString());
        gcConfigSection.put("GC_TIME_RATIO_MIN", items.getAggregate(JdkAggregators.GC_TIME_RATIO_MIN).displayUsing(IDisplayable.AUTO));
        gcConfigurationNode.set("GC_CONFIG_SECTION", gcConfigSection);

        ObjectNode heapConfigSection = mapper.createObjectNode();
        heapConfigSection.put("HEAP_CONF_INITIAL_SIZE_MIN", items.getAggregate(JdkAggregators.HEAP_CONF_INITIAL_SIZE_MIN).displayUsing(IDisplayable.AUTO));
        heapConfigSection.put("HEAP_CONF_MIN_SIZE", items.getAggregate(JdkAggregators.HEAP_CONF_MIN_SIZE).displayUsing(IDisplayable.AUTO));
        heapConfigSection.put("HEAP_CONF_MAX_SIZE", items.getAggregate(JdkAggregators.HEAP_CONF_MAX_SIZE).displayUsing(IDisplayable.AUTO));
        heapConfigSection.put("USE_COMPRESSED_OOPS", items.getAggregate(JdkAggregators.USE_COMPRESSED_OOPS).toString());
        heapConfigSection.put("COMPRESSED_OOPS_MODE", items.getAggregate(JdkAggregators.COMPRESSED_OOPS_MODE));
        heapConfigSection.put("HEAP_ADDRESS_SIZE_MIN", items.getAggregate(JdkAggregators.HEAP_ADDRESS_SIZE_MIN).displayUsing(IDisplayable.AUTO));
        heapConfigSection.put("HEAP_OBJECT_ALIGNMENT_MIN", items.getAggregate(JdkAggregators.HEAP_OBJECT_ALIGNMENT_MIN).displayUsing(IDisplayable.AUTO));
        gcConfigurationNode.set("HEAP_CONFIG_SECTION", heapConfigSection);

        ObjectNode ycConfigSection = mapper.createObjectNode();
        ycConfigSection.put("YOUNG_GENERATION_MIN_SIZE", items.getAggregate(JdkAggregators.YOUNG_GENERATION_MIN_SIZE).displayUsing(IDisplayable.AUTO));
        ycConfigSection.put("YOUNG_GENERATION_MAX_SIZE", items.getAggregate(JdkAggregators.YOUNG_GENERATION_MAX_SIZE).displayUsing(IDisplayable.AUTO));
        ycConfigSection.put("NEW_RATIO_MIN", items.getAggregate(JdkAggregators.NEW_RATIO_MIN).displayUsing(IDisplayable.AUTO));
        ycConfigSection.put("TENURING_THRESHOLD_INITIAL_MIN", items.getAggregate(JdkAggregators.TENURING_THRESHOLD_INITIAL_MIN).displayUsing(IDisplayable.AUTO));
        ycConfigSection.put("TENURING_THRESHOLD_MAX", items.getAggregate(JdkAggregators.TENURING_THRESHOLD_MAX).displayUsing(IDisplayable.AUTO));
        ycConfigSection.put("USE_TLABS", items.getAggregate(JdkAggregators.USES_TLABS).toString());
        ycConfigSection.put("TLAB_MIN_SIZE", items.getAggregate(JdkAggregators.TLAB_MIN_SIZE).displayUsing(IDisplayable.AUTO));
        ycConfigSection.put("TLAB_REFILL_WASTE_LIMIT_MIN", items.getAggregate(JdkAggregators.TLAB_REFILL_WASTE_LIMIT_MIN).displayUsing(IDisplayable.AUTO));
        gcConfigurationNode.set("YC_CONFIG_SECTION", ycConfigSection);

        rootNode.set("GC_CONFIGURATION", gcConfigurationNode);
        return mapper.writeValueAsString(rootNode);
    }

    public IItemCollection getItemsFromArchivedInputStream(String jvmId, String recordingName)
            throws IOException, CouldNotLoadRecordingException {
        return JfrLoaderToolkit.loadEvents(
                recordingHelper.getArchivedRecordingStream(jvmId, recordingName));
    }
}
