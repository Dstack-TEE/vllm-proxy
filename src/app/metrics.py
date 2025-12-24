from prometheus_client import Counter, REGISTRY, generate_latest

# Custom metrics
# By default, metrics are registered to REGISTRY
vllm_proxy_errors_total = Counter(
    "vllm_proxy_errors_total",
    "Total number of unhandled exceptions in the vLLM proxy",
    ["type"]
)

def get_proxy_metrics() -> str:
    """
    Get the current proxy metrics from the prometheus-client registry.
    """
    return generate_latest(REGISTRY).decode("utf-8")

