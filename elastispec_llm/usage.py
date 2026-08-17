from __future__ import annotations

from typing import Any


TOKEN_USAGE_KEYS = (
    "input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "reasoning_tokens",
    "tool_tokens",
    "total_tokens",
    "search_queries",
)


def safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def empty_usage_summary() -> dict[str, Any]:
    totals = {key: 0 for key in TOKEN_USAGE_KEYS}
    totals.update(
        {
            "call_count": 0,
            "elapsed_seconds": 0.0,
        }
    )
    return totals


def summarize_provider_calls(calls: list[dict[str, Any]]) -> dict[str, Any]:
    summary = empty_usage_summary()
    summary["call_count"] = len(calls)
    for call in calls:
        usage = call.get("usage", {}) or {}
        for key in TOKEN_USAGE_KEYS:
            summary[key] += safe_int(usage.get(key))
        try:
            summary["elapsed_seconds"] += float(call.get("elapsed_seconds", 0) or 0)
        except (TypeError, ValueError):
            pass
    return summary


def token_cost_components(
    usage: dict[str, Any],
    rates: dict[str, Any],
    divisor: int,
) -> dict[str, float]:
    components: dict[str, float] = {}
    input_tokens = safe_int(usage.get("input_tokens"))
    cached_input_tokens = min(
        safe_int(usage.get("cached_input_tokens")),
        input_tokens,
    )
    cached_input_rate = rates.get("cached_input_tokens")
    uncached_input_tokens = (
        input_tokens - cached_input_tokens
        if cached_input_rate is not None
        else input_tokens
    )

    input_rate = rates.get("input_tokens")
    if input_rate is not None:
        components["input_tokens"] = (
            uncached_input_tokens / divisor
        ) * float(input_rate)
    if cached_input_rate is not None:
        components["cached_input_tokens"] = (
            cached_input_tokens / divisor
        ) * float(cached_input_rate)

    for usage_key in ("output_tokens", "reasoning_tokens", "tool_tokens"):
        rate = rates.get(usage_key)
        if rate is None:
            continue
        components[usage_key] = (
            safe_int(usage.get(usage_key)) / divisor
        ) * float(rate)
    return components


def estimate_cost(
    summary: dict[str, Any],
    pricing: dict[str, Any],
    *,
    provider: str,
    model: str,
    calls: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    provider_pricing = ((pricing.get("providers", {}) or {}).get(provider, {}) or {})
    model_pricing = ((provider_pricing.get("models", {}) or {}).get(model, {}) or {})
    unit = model_pricing.get("unit", "per_1m_tokens")
    tiers = model_pricing.get("tiers", []) or []
    rates = model_pricing.get("rates", {}) or {}

    if tiers:
        return estimate_tiered_cost(calls or [], model_pricing, provider=provider, model=model)

    if not rates:
        return {
            "estimated_cost_usd": None,
            "pricing_found": False,
            "pricing_unit": unit,
            "note": f"No pricing entry for {provider}/{model}.",
        }

    divisor = 1_000_000 if unit == "per_1m_tokens" else 1
    components = token_cost_components(summary, rates, divisor)
    total = sum(components.values())

    search_rate = rates.get("search_queries")
    if search_rate is not None:
        component = safe_int(summary.get("search_queries")) * float(search_rate)
        components["search_queries"] = component
        total += component

    return {
        "estimated_cost_usd": total,
        "pricing_found": True,
        "pricing_unit": unit,
        "components": components,
        "source": model_pricing.get("source", ""),
        "notes": model_pricing.get("notes", []),
    }


def estimate_tiered_cost(
    calls: list[dict[str, Any]],
    model_pricing: dict[str, Any],
    *,
    provider: str,
    model: str,
) -> dict[str, Any]:
    unit = model_pricing.get("unit", "per_1m_tokens")
    divisor = 1_000_000 if unit == "per_1m_tokens" else 1
    tiers = model_pricing.get("tiers", []) or []
    if not tiers:
        return {
            "estimated_cost_usd": None,
            "pricing_found": False,
            "pricing_unit": unit,
            "note": f"No pricing tiers for {provider}/{model}.",
        }

    total = 0.0
    components = {key: 0.0 for key in TOKEN_USAGE_KEYS}
    tier_usage: dict[str, dict[str, Any]] = {}
    for call in calls:
        usage = call.get("usage", {}) or {}
        tier = select_tier(tiers, safe_int(usage.get("input_tokens")))
        tier_name = tier.get("name", "default")
        rates = tier.get("rates", {}) or {}
        tier_usage.setdefault(tier_name, {"call_count": 0, "cost_usd": 0.0})
        tier_usage[tier_name]["call_count"] += 1

        call_components = token_cost_components(usage, rates, divisor)
        for usage_key, component in call_components.items():
            components[usage_key] += component
            tier_usage[tier_name]["cost_usd"] += component
            total += component

        search_rate = rates.get("search_queries")
        if search_rate is not None:
            component = safe_int(usage.get("search_queries")) * float(search_rate)
            components["search_queries"] += component
            tier_usage[tier_name]["cost_usd"] += component
            total += component

    return {
        "estimated_cost_usd": total,
        "pricing_found": True,
        "pricing_unit": unit,
        "components": {key: value for key, value in components.items() if value},
        "tier_usage": tier_usage,
        "source": model_pricing.get("source", ""),
        "notes": model_pricing.get("notes", []),
    }


def select_tier(tiers: list[dict[str, Any]], input_tokens: int) -> dict[str, Any]:
    for tier in tiers:
        min_tokens = tier.get("min_input_tokens")
        max_tokens = tier.get("max_input_tokens")
        if min_tokens is not None and input_tokens < safe_int(min_tokens):
            continue
        if max_tokens is not None and input_tokens > safe_int(max_tokens):
            continue
        return tier
    return tiers[-1]


def estimate_cost_for_calls(calls: list[dict[str, Any]], pricing: dict[str, Any]) -> dict[str, Any]:
    if not calls:
        return {
            "estimated_cost_usd": 0.0,
            "pricing_found": True,
            "groups": {},
        }

    grouped_calls: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for call in calls:
        provider = str(call.get("provider", ""))
        model = str(call.get("model", ""))
        grouped_calls.setdefault((provider, model), []).append(call)

    total = 0.0
    any_pricing_found = False
    missing_pricing: list[str] = []
    groups: dict[str, Any] = {}
    for (provider, model), group_calls in sorted(grouped_calls.items()):
        group_summary = summarize_provider_calls(group_calls)
        group_cost = estimate_cost(
            group_summary,
            pricing,
            provider=provider,
            model=model,
            calls=group_calls,
        )
        group_key = f"{provider}/{model}"
        groups[group_key] = {
            "usage_summary": group_summary,
            "cost_summary": group_cost,
        }
        if group_cost.get("estimated_cost_usd") is None:
            missing_pricing.append(group_key)
            continue
        any_pricing_found = True
        total += float(group_cost.get("estimated_cost_usd") or 0)

    return {
        "estimated_cost_usd": total if any_pricing_found else None,
        "pricing_found": any_pricing_found,
        "pricing_complete": not missing_pricing,
        "missing_pricing": missing_pricing,
        "groups": groups,
    }
