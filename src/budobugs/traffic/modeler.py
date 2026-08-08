"""Endpoint, parameter, object, and account-difference modeling."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Literal
from urllib.parse import parse_qsl, urljoin, urlsplit

from budobugs.core.identifiers import new_id
from budobugs.models import (
    EndpointFamily,
    HttpExchange,
    ObjectReference,
    Parameter,
    Role,
    StateTransition,
    Tenant,
)
from budobugs.traffic.normalization import (
    canonicalize_url,
    classify_value,
    extract_graphql_operation,
    infer_json_schema,
    is_static_asset,
    path_template,
    structure_similarity,
)

ParameterLocation = Literal["path", "query", "header", "cookie", "body", "graphql"]
_FRONTEND_LINK = re.compile(
    r"(?:fetch\s*\(|href\s*=|src\s*=)\s*[\"'](?P<url>[^\"']{1,2048})",
    re.IGNORECASE,
)
_JS_API_PATH = re.compile(r"[\"'](?P<url>/(?:api|graphql|v\d+)(?:/[^\"'\s]*)?)[\"']", re.IGNORECASE)


@dataclass(slots=True)
class TrafficModel:
    endpoint_families: list[EndpointFamily]
    parameters: dict[str, list[Parameter]]
    objects: list[ObjectReference]
    account_differences: list[dict[str, object]]
    roles: list[Role]
    tenants: list[Tenant]
    state_transitions: list[StateTransition]
    response_schemas: dict[str, dict[str, object]]
    frontend_api_links: list[dict[str, str]]
    api_schema_clues: list[dict[str, str]]
    historical_urls: list[str]
    discarded_static_exchange_ids: list[str]

    def as_dict(self) -> dict[str, object]:
        return {
            "endpoint_families": [item.model_dump(mode="json") for item in self.endpoint_families],
            "parameters": {
                key: [item.model_dump(mode="json") for item in values] for key, values in self.parameters.items()
            },
            "objects": [item.model_dump(mode="json") for item in self.objects],
            "account_differences": self.account_differences,
            "roles": [item.model_dump(mode="json") for item in self.roles],
            "tenants": [item.model_dump(mode="json") for item in self.tenants],
            "state_transitions": [item.model_dump(mode="json") for item in self.state_transitions],
            "response_schemas": self.response_schemas,
            "frontend_api_links": self.frontend_api_links,
            "api_schema_clues": self.api_schema_clues,
            "historical_urls": self.historical_urls,
            "discarded_static_exchange_ids": self.discarded_static_exchange_ids,
        }


def build_traffic_model(exchanges: list[HttpExchange]) -> TrafficModel:
    discarded_static = [
        item.exchange_id
        for item in exchanges
        if is_static_asset(item.url, _header(item.response_headers, "content-type"))
    ]
    discarded_ids = set(discarded_static)
    modeled = [item for item in exchanges if item.exchange_id not in discarded_ids]
    groups: dict[tuple[str, str, str], list[HttpExchange]] = defaultdict(list)
    for exchange in modeled:
        parsed = urlsplit(exchange.url)
        groups[(parsed.netloc.lower(), exchange.method, path_template(exchange.url))].append(exchange)
    families: list[EndpointFamily] = []
    parameters: dict[str, list[Parameter]] = {}
    objects: list[ObjectReference] = []
    differences: list[dict[str, object]] = []
    transitions: list[StateTransition] = []
    response_schemas: dict[str, dict[str, object]] = {}
    for (host, method, template), members in sorted(groups.items()):
        family_id = new_id("endpoint")
        statuses = Counter(item.response_status for item in members)
        lengths = [len(item.response_body or "") for item in members]
        family_parameters = _parameters(members)
        family = EndpointFamily(
            family_id=family_id,
            host=host,
            method=method,
            path_template=template,
            exchange_ids=[item.exchange_id for item in members],
            parameter_names=sorted({item.name for item in family_parameters}),
            status_baseline=dict(statuses),
            response_length_baseline=(min(lengths), max(lengths)) if lengths else None,
            anomaly_score=_anomaly_score(members),
        )
        families.append(family)
        parameters[family_id] = family_parameters
        objects.extend(_objects(members))
        differences.extend(_account_differences(family_id, members))
        transitions.extend(_state_transitions(family, members))
        schema = _response_schema(members)
        if schema is not None:
            response_schemas[family_id] = schema
    links, clues = _frontend_and_schema_clues(modeled)
    return TrafficModel(
        endpoint_families=families,
        parameters=parameters,
        objects=_deduplicate_objects(objects),
        account_differences=differences,
        roles=_roles(modeled),
        tenants=_tenants(modeled),
        state_transitions=transitions,
        response_schemas=response_schemas,
        frontend_api_links=links,
        api_schema_clues=clues,
        historical_urls=_canonical_urls(exchanges),
        discarded_static_exchange_ids=discarded_static,
    )


def _parameter_values(exchanges: list[HttpExchange]) -> dict[tuple[ParameterLocation, str], list[str]]:
    values: dict[tuple[ParameterLocation, str], list[str]] = defaultdict(list)
    for exchange in exchanges:
        for name, value in parse_qsl(urlsplit(exchange.url).query, keep_blank_values=True):
            values[("query", name)].append(value)
        actual_segments = [segment for segment in urlsplit(exchange.url).path.split("/") if segment]
        template_segments = [segment for segment in path_template(exchange.url).split("/") if segment]
        for index, (actual, template) in enumerate(zip(actual_segments, template_segments, strict=False)):
            if template in {"{id}", "{uuid}", "{token}"}:
                values[("path", f"path_{template[1:-1]}_{index}")].append(actual)
        for name, value in exchange.request_headers.items():
            lowered = name.lower()
            if lowered == "cookie":
                values[("cookie", "cookie")].append(value)
            elif lowered in {"authorization", "x-api-key", "x-auth-token"} or lowered.startswith("x-"):
                values[("header", name)].append(value)
        if exchange.request_body:
            try:
                body = json.loads(exchange.request_body)
            except json.JSONDecodeError:
                continue
            if isinstance(body, dict):
                variables = body.get("variables")
                if isinstance(variables, dict):
                    for name, value in variables.items():
                        if isinstance(value, (str, int, float, bool)):
                            values[("graphql", str(name))].append(str(value))
                for name, value in body.items():
                    if name != "variables" and isinstance(value, (str, int, float, bool)):
                        location: ParameterLocation = "graphql" if name in {"operationName", "query"} else "body"
                        values[(location, str(name))].append(str(value))
    return values


def _parameters(exchanges: list[HttpExchange]) -> list[Parameter]:
    values = _parameter_values(exchanges)
    result: list[Parameter] = []
    for (location, name), samples in sorted(values.items()):
        kinds = Counter(classify_value(value, name) for value in samples)
        dynamic = kinds.most_common(1)[0][0]
        result.append(
            Parameter(
                name=name,
                location=location,
                inferred_type=_sample_type(samples),
                sample_values=list(dict.fromkeys(samples))[:10],
                dynamic_kind=dynamic,  # type: ignore[arg-type]
                sensitive=dynamic == "secret",
            )
        )
    return result


def _sample_type(samples: list[str]) -> str:
    if samples and all(value.lower() in {"true", "false"} for value in samples):
        return "boolean"
    if samples and all(value.lstrip("-").isdigit() for value in samples):
        return "integer"
    try:
        if samples and all(float(value) == float(value) for value in samples):
            return "number"
    except ValueError:
        pass
    return "string"


def _objects(exchanges: list[HttpExchange]) -> list[ObjectReference]:
    result: list[ObjectReference] = []
    for exchange in exchanges:
        segments = [segment for segment in urlsplit(exchange.url).path.split("/") if segment]
        for index, segment in enumerate(segments):
            if segment.isdigit() or (len(segment) == 36 and segment.count("-") == 4):
                object_type = segments[index - 1] if index else "object"
                result.append(
                    ObjectReference(
                        object_id=segment,
                        object_type=object_type.rstrip("s"),
                        owner_account_alias=exchange.account_alias,
                        tenant_id=exchange.tenant_id,
                        source_exchange_ids=[exchange.exchange_id],
                    )
                )
    return result


def _deduplicate_objects(objects: list[ObjectReference]) -> list[ObjectReference]:
    merged: dict[tuple[str, str], ObjectReference] = {}
    for item in objects:
        key = (item.object_type, item.object_id)
        if key not in merged:
            merged[key] = item
        else:
            merged[key].source_exchange_ids.extend(item.source_exchange_ids)
            if merged[key].owner_account_alias is None:
                merged[key].owner_account_alias = item.owner_account_alias
    return list(merged.values())


def _account_differences(family_id: str, exchanges: list[HttpExchange]) -> list[dict[str, object]]:
    by_alias: dict[str, list[HttpExchange]] = defaultdict(list)
    for exchange in exchanges:
        by_alias[exchange.account_alias or "anonymous"].append(exchange)
    aliases = sorted(by_alias)
    differences: list[dict[str, object]] = []
    for index, left_alias in enumerate(aliases):
        for right_alias in aliases[index + 1 :]:
            left = by_alias[left_alias][0]
            right = by_alias[right_alias][0]
            differences.append(
                {
                    "endpoint_family_id": family_id,
                    "left_account": left_alias,
                    "right_account": right_alias,
                    "left_status": left.response_status,
                    "right_status": right.response_status,
                    "structure_similarity": structure_similarity(left.response_body, right.response_body),
                    "same_response_hash": left.response_hash == right.response_hash,
                }
            )
    return differences


def _header(headers: dict[str, str], name: str) -> str | None:
    lowered = name.lower()
    return next((value for key, value in headers.items() if key.lower() == lowered), None)


def _roles(exchanges: list[HttpExchange]) -> list[Role]:
    privileges: dict[str, set[str]] = defaultdict(set)
    for exchange in exchanges:
        if exchange.role_id:
            privileges[exchange.role_id].add(f"{exchange.method} {path_template(exchange.url)}")
    return [
        Role(role_id=role_id, name=role_id, privileges=sorted(values)) for role_id, values in sorted(privileges.items())
    ]


def _tenants(exchanges: list[HttpExchange]) -> list[Tenant]:
    accounts: dict[str, set[str]] = defaultdict(set)
    for exchange in exchanges:
        if exchange.tenant_id and exchange.account_alias:
            accounts[exchange.tenant_id].add(exchange.account_alias)
    return [
        Tenant(tenant_id=tenant_id, name=tenant_id, account_aliases=sorted(values))
        for tenant_id, values in sorted(accounts.items())
    ]


def _json_object(body: str | None) -> dict[str, object]:
    if not body or len(body) > 2 * 1024 * 1024:
        return {}
    try:
        decoded = json.loads(body)
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _state_value(payload: dict[str, object], names: tuple[str, ...]) -> str | None:
    for name in names:
        value = payload.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _state_transitions(family: EndpointFamily, exchanges: list[HttpExchange]) -> list[StateTransition]:
    if family.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return []
    results: list[StateTransition] = []
    for exchange in exchanges:
        request = _json_object(exchange.request_body)
        response = _json_object(exchange.response_body)
        before = _state_value(response, ("previous", "from", "from_state", "state_before")) or _state_value(
            request, ("previous", "from", "from_state", "state_before")
        )
        after = _state_value(response, ("current", "to", "to_state", "state_after")) or _state_value(
            request, ("state", "status", "current", "to", "to_state")
        )
        if before is None or after is None or before == after:
            continue
        segments = [item for item in family.path_template.split("/") if item and not item.startswith("{")]
        object_type = segments[-2] if len(segments) > 1 else segments[-1] if segments else "resource"
        results.append(
            StateTransition(
                transition_id=new_id("transition"),
                object_type=object_type.rstrip("s"),
                from_state=before,
                to_state=after,
                endpoint_family_id=family.family_id,
                required_roles=[exchange.role_id] if exchange.role_id else [],
                reversible=False,
            )
        )
    return results


def _response_schema(exchanges: list[HttpExchange]) -> dict[str, object] | None:
    schemas: dict[str, dict[str, object]] = {}
    for exchange in exchanges[:50]:
        if not exchange.response_body or len(exchange.response_body) > 2 * 1024 * 1024:
            continue
        try:
            decoded = json.loads(exchange.response_body)
        except json.JSONDecodeError:
            continue
        schema = infer_json_schema(decoded)
        schemas[json.dumps(schema, sort_keys=True)] = schema
    if not schemas:
        return None
    if len(schemas) == 1:
        return next(iter(schemas.values()))
    return {"anyOf": [schemas[key] for key in sorted(schemas)]}


def _frontend_and_schema_clues(
    exchanges: list[HttpExchange],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    links: dict[tuple[str, str, str], dict[str, str]] = {}
    clues: dict[tuple[str, str, str], dict[str, str]] = {}
    for exchange in exchanges:
        body = (exchange.response_body or "")[: 2 * 1024 * 1024]
        content_type = (_header(exchange.response_headers, "content-type") or "").lower()
        is_html = "html" in content_type or "<html" in body.lower() or "<!doctype" in body.lower()
        if is_html:
            for match in _FRONTEND_LINK.finditer(body):
                value = match.group("url")
                if value.startswith(("javascript:", "data:", "mailto:")):
                    continue
                resolved = urljoin(exchange.url, value)
                record = {
                    "frontend_url": exchange.url,
                    "api_or_route_url": resolved,
                    "exchange_id": exchange.exchange_id,
                }
                links[(exchange.url, resolved, exchange.exchange_id)] = record
        is_javascript = "javascript" in content_type or urlsplit(exchange.url).path.lower().endswith(".js")
        if is_javascript:
            for match in _JS_API_PATH.finditer(body):
                resolved = urljoin(exchange.url, match.group("url"))
                record = {"kind": "javascript-endpoint", "value": resolved, "exchange_id": exchange.exchange_id}
                clues[(record["kind"], record["value"], record["exchange_id"])] = record

        operation_name, operation_kind = extract_graphql_operation(exchange.request_body)
        if operation_name or operation_kind:
            value = f"{operation_kind or 'operation'}:{operation_name or '<anonymous>'}"
            record = {"kind": "graphql-operation", "value": value, "exchange_id": exchange.exchange_id}
            clues[(record["kind"], record["value"], record["exchange_id"])] = record
        lowered_material = f"{urlsplit(exchange.url).path}\n{body[:100_000]}".lower()
        for marker, kind in (("openapi", "openapi"), ("swagger", "swagger"), ("postman", "postman")):
            if marker in lowered_material:
                record = {"kind": kind, "value": exchange.url, "exchange_id": exchange.exchange_id}
                clues[(record["kind"], record["value"], record["exchange_id"])] = record
    return list(links.values()), list(clues.values())


def _canonical_urls(exchanges: list[HttpExchange]) -> list[str]:
    values: set[str] = set()
    for exchange in exchanges:
        try:
            values.add(canonicalize_url(exchange.url))
        except ValueError:
            values.add(exchange.url)
    return sorted(values)


def _anomaly_score(exchanges: list[HttpExchange]) -> float:
    statuses = {item.response_status for item in exchanges}
    lengths = [len(item.response_body or "") for item in exchanges]
    status_component = min(1.0, max(0, len(statuses) - 1) * 0.35)
    length_component = 0.0
    if lengths and max(lengths) > 0:
        length_component = min(0.65, (max(lengths) - min(lengths)) / max(lengths))
    return round(min(1.0, status_component + length_component), 4)
