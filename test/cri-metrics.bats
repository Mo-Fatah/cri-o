#!/usr/bin/env bats
# vim: set syntax=sh:

load helpers

function setup() {
    setup_test

    PORT="9090"
    CONTAINER_ENABLE_METRICS="true" start_crio
    if ! port_listens "$PORT"; then
        echo "Port $PORT is not listening" 
        exit 1
    fi

}

function teardown() {
    cleanup_test
}

function metrics_setup() {
    # start sandbox
    POD_ID=$(crictl runp "$TESTDATA/sandbox_config.json")
    # Make sure we get a non-empty metrics response
    crictl metricsp | grep "podSandboxId"
    CONTAINER_ID=$(crictl create $POD_ID "$TESTDATA/container_sleep.json" "$TESTDATA/sandbox_config.json")
    crictl start $CONTAINER_ID
    # assert pod metrics are present
    crictl metricsp | grep "container_network_receive_bytes_total"
    # assert container metrics are present
    crictl metricsp | grep "container_memory_usage_bytes"
}

@test "default metrics are present" {
    metrics_setup 
}

@test "verify container_memory_usage_bytes" {
    metrics_setup

    set_container_pod_cgroup_root "" "$CONTAINER_ID"

    cmd='for i in {1..10}; do dd if=/dev/zero of=/dev/null bs=10M count=1; done'
    crictl exec --sync "$CONTAINER_ID" /bin/sh -c "$cmd"

    # Get the memory.current value from the cgroup
    cgroup_memory_current=$(cat $CTR_CGROUP/memory.current)
    metrics_memory_usage=$(crictl metricsp | jq '.podMetrics[0].containerMetrics[0].metrics[] | select(.name == "container_memory_usage_bytes") | .value.value | tonumber')
    echo "cgroup_memory_current: $cgroup_memory_current"
    echo "metrics_memory_usage: $metrics_memory_usage"
    
    # FAILING
    [[ cgroup_memory_current == metrics_memory_usage ]]
}

@test "verify container_oom_events_total" {
    # start sandbox
    POD_ID=$(crictl runp "$TESTDATA/sandbox_config.json")
    CONTAINER_ID=$(crictl create $POD_ID "$TESTDATA/container_sleep.json" "$TESTDATA/sandbox_config.json")
    crictl start $CONTAINER_ID

    set_container_pod_cgroup_root "" "$CONTAINER_ID"

    cmd='dd if=/dev/zero of=/dev/shm/fill bs=1k count=1024M'
    # This command will cause the container to OOM but will also exit and cause the container to be removed
    crictl exec --sync "$CONTAINER_ID" /bin/sh -c "$cmd" 
    metrics_oom_events_total=$(crictl metricsp | jq '.podMetrics[0].containerMetrics[0].metrics[] | select(.name == "container_oom_events_total") | .value.value')
}

@test "verify container_memory_working_set_bytes" {
    # According to cAdvisor code:
    # container_memory_working_set_bytes = memory.current - memory.stat:inactive_file in the cgroup,
    # see: https://github.com/google/cadvisor/blob/bf2a7fee4170e418e7ac774af7679257fe26dc69/container/libcontainer/handler.go#L837-L845
    # Assuming that cAdvisor consider Memory.Usage = memory.current , then the above formula should be our bar for testing.

    metrics_setup

    set_container_pod_cgroup_root "" "$CONTAINER_ID"
    
    cmd='myarray=(); for i in {1..1000}; do myarray+=(\"$(date)\"); done'
    crictl exec  --sync "$CONTAINER_ID" /bin/sh -c "$cmd" 
    
    cgroup_memory_inactive_file=$(cat $CTR_CGROUP/memory.stat | grep inactive_file | awk '{print $2}') && \
    cgroup_memory_current=$(cat $CTR_CGROUP/memory.current) && \
    metrics_memory_working_set=$(crictl metricsp | jq '.podMetrics[0].containerMetrics[0].metrics[] | select(.name == "container_memory_working_set_bytes") | .value.value | tonumber')

    # FAILING
    [[ $metrics_memory_working_set == $((cgroup_memory_current - cgroup_memory_inactive_file)) ]]

    # READ: 
    #   - https://github.com/google/cadvisor/issues/2582#issuecomment-644883028
    #   - https://github.com/google/cadvisor/issues/3286
    #   - https://mohamedmsaeed.medium.com/memory-working-set-vs-memory-rss-in-kubernetes-which-one-you-should-monitor-8ef77bf0acee
}

@test "verify container_memory_rss" {
    # Memory RSS doesn't exist in cgroup v2
}

@test "verify container_memory_cache" {
    # container_memory_cache reflects the memory.stat:file value
    # see: https://github.com/google/cadvisor/issues/2604#issuecomment-1112066109

    metrics_setup

    set_container_pod_cgroup_root "" "$CONTAINER_ID"
    
    # This doesn't 
    cmd='for i in {1..10}; do dd if=/dev/zero of=/dev/null; echo "Iteration $i";done'
    output=$(crictl exec  --sync "$CONTAINER_ID" dnf5 install https://packages.fedoraproject.org/pkgs/stress/stress)
    echo "$output" >&3

    #crictl metricsp >&3
    #cmd='myarray=(); touch /dev/tmpfile; for i in {1..10000}; do myarray+=(\"$(date)\"); date >> /dev/tmpfile; done'
    #output=$(crictl exec  --sync "$CONTAINER_ID" /bin/sh -c "$cmd")
    #output=$(crictl exec  --sync "$CONTAINER_ID" cat /dev/tmpfile)
    #echo "$output" >&3
    #crictl metricsp >&3

}



# 
# for incerementing memory usage, use this:
#cmd='for i in {1..10}; do dd if=/dev/zero of=/dev/null bs=10M count=1; echo "Iteration $i"; sleep 1; done'
# "myarray=(); while true; do myarray+=(\"$(date)\"); echo 'hello'; done"