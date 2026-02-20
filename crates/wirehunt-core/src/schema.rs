use serde_json;

pub fn generate_report_schema() -> String {
    let schema = serde_json::to_string_pretty(&serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://wirehunt.dev/schemas/report_v1.schema.json",
        "title": "WireHunt Report v1",
        "description": "Primary API contract between WireHunt engine, CLI, TUI, and AI layer",
        "type": "object",
        "properties": {
            "metadata": { "$ref": "#/$defs/ReportMetadata" },
            "findings": { "type": "array", "items": { "$ref": "#/$defs/Finding" } },
            "flows": { "type": "array", "items": { "$ref": "#/$defs/Flow" } },
            "streams": { "type": "array", "items": { "$ref": "#/$defs/Stream" } },
            "artifacts": { "type": "array", "items": { "$ref": "#/$defs/Artifact" } },
            "credentials": { "type": "array", "items": { "$ref": "#/$defs/Credential" } },
            "iocs": { "type": "array", "items": { "$ref": "#/$defs/Ioc" } },
            "dns_records": { "type": "array", "items": { "$ref": "#/$defs/DnsRecord" } },
            "http_transactions": { "type": "array", "items": { "$ref": "#/$defs/HttpTransaction" } },
            "tls_sessions": { "type": "array", "items": { "$ref": "#/$defs/TlsInfo" } },
            "host_profiles": { "type": "array", "items": { "$ref": "#/$defs/HostProfile" } },
            "timeline": { "type": "array", "items": { "$ref": "#/$defs/TimelineEvent" } },
            "statistics": { "$ref": "#/$defs/AnalysisStatistics" }
        },
        "required": ["metadata", "findings", "flows", "streams", "artifacts", "credentials", "iocs", "statistics"],
        "$defs": {
            "ReportMetadata": {
                "type": "object",
                "properties": {
                    "wirehunt_version": { "type": "string" },
                    "generated_at": { "type": "string", "format": "date-time" },
                    "pcap_filename": { "type": "string" },
                    "pcap_sha256": { "type": "string" },
                    "pcap_size_bytes": { "type": "integer" },
                    "total_packets": { "type": "integer" },
                    "capture_start": { "type": ["string", "null"], "format": "date-time" },
                    "capture_end": { "type": ["string", "null"], "format": "date-time" },
                    "capture_duration_secs": { "type": "number" },
                    "profile": { "type": "string", "enum": ["ctf", "incident_response", "forensics", "threat_hunt", "quick"] }
                },
                "required": ["wirehunt_version", "generated_at", "pcap_filename", "pcap_sha256", "profile"]
            },
            "EvidenceRef": {
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "kind": { "type": "string", "enum": ["pcap_packet", "reassembled_stream", "extracted_artifact", "decoded_content", "protocol_field"] },
                    "pcap_offset": { "type": ["integer", "null"] },
                    "stream_id": { "type": ["string", "null"] },
                    "artifact_id": { "type": ["string", "null"] },
                    "packet_range": {},
                    "description": { "type": "string" }
                },
                "required": ["id", "kind", "description"]
            },
            "Finding": {
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "title": { "type": "string" },
                    "description": { "type": "string" },
                    "severity": { "type": "string", "enum": ["info", "low", "medium", "high", "critical"] },
                    "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                    "category": { "type": "string" },
                    "evidence": { "type": "array", "items": { "$ref": "#/$defs/EvidenceRef" }, "minItems": 1 },
                    "pivots": { "type": "array" },
                    "mitre_attack": { "type": "array", "items": { "type": "string" } },
                    "tags": { "type": "array", "items": { "type": "string" } },
                    "timestamp": { "type": "string", "format": "date-time" }
                },
                "required": ["id", "title", "severity", "confidence", "category", "evidence"]
            },
            "Flow": {
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "key": { "$ref": "#/$defs/FlowKey" },
                    "start_time": { "type": "string", "format": "date-time" },
                    "end_time": { "type": "string", "format": "date-time" },
                    "duration_us": { "type": "integer" },
                    "packet_count": { "type": "integer" },
                    "byte_count": { "type": "integer" },
                    "detected_protocol": { "type": ["string", "null"] }
                },
                "required": ["id", "key", "start_time", "packet_count", "byte_count"]
            },
            "FlowKey": {
                "type": "object",
                "properties": {
                    "src_ip": { "type": "string" },
                    "dst_ip": { "type": "string" },
                    "src_port": { "type": "integer" },
                    "dst_port": { "type": "integer" },
                    "protocol": { "type": "string" }
                },
                "required": ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]
            },
            "Stream": {
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "flow_id": { "type": "string" },
                    "protocol": { "type": "string" },
                    "total_bytes": { "type": "integer" },
                    "summary": { "type": ["string", "null"] }
                },
                "required": ["id", "flow_id", "protocol", "total_bytes"]
            },
            "Artifact": {
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "kind": { "type": "string" },
                    "name": { "type": ["string", "null"] },
                    "mime_type": { "type": ["string", "null"] },
                    "size_bytes": { "type": "integer" },
                    "sha256": { "type": "string" },
                    "md5": { "type": "string" },
                    "path": { "type": ["string", "null"] }
                },
                "required": ["id", "kind", "size_bytes", "sha256"]
            },
            "Credential": {
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "kind": { "type": "string" },
                    "username": { "type": ["string", "null"] },
                    "secret": { "type": "string" },
                    "service": { "type": ["string", "null"] },
                    "host": { "type": ["string", "null"] },
                    "evidence": { "$ref": "#/$defs/EvidenceRef" }
                },
                "required": ["id", "kind", "secret", "evidence"]
            },
            "Ioc": {
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "kind": { "type": "string" },
                    "value": { "type": "string" },
                    "confidence": { "type": "number" },
                    "evidence": { "type": "array", "items": { "$ref": "#/$defs/EvidenceRef" } }
                },
                "required": ["id", "kind", "value", "confidence"]
            },
            "DnsRecord": {
                "type": "object",
                "properties": {
                    "query_name": { "type": "string" },
                    "record_type": { "type": "string" },
                    "response_data": { "type": "array", "items": { "type": "string" } },
                    "is_response": { "type": "boolean" }
                },
                "required": ["query_name", "record_type", "is_response"]
            },
            "HttpTransaction": {
                "type": "object",
                "properties": {
                    "method": { "type": "string" },
                    "uri": { "type": "string" },
                    "host": { "type": ["string", "null"] },
                    "status_code": { "type": ["integer", "null"] },
                    "content_type": { "type": ["string", "null"] },
                    "user_agent": { "type": ["string", "null"] }
                },
                "required": ["method", "uri"]
            },
            "TlsInfo": {
                "type": "object",
                "properties": {
                    "version": { "type": "string" },
                    "sni": { "type": ["string", "null"] },
                    "ja3_hash": { "type": ["string", "null"] },
                    "ja3s_hash": { "type": ["string", "null"] },
                    "cipher_suite": { "type": ["string", "null"] },
                    "is_self_signed": { "type": ["boolean", "null"] }
                },
                "required": ["version"]
            },
            "HostProfile": {
                "type": "object",
                "properties": {
                    "ip": { "type": "string" },
                    "hostnames": { "type": "array", "items": { "type": "string" } },
                    "services": { "type": "array" },
                    "total_bytes_sent": { "type": "integer" },
                    "total_bytes_received": { "type": "integer" }
                },
                "required": ["ip"]
            },
            "TimelineEvent": {
                "type": "object",
                "properties": {
                    "timestamp": { "type": "string", "format": "date-time" },
                    "event_type": { "type": "string" },
                    "summary": { "type": "string" },
                    "severity": { "type": "string" }
                },
                "required": ["timestamp", "event_type", "summary", "severity"]
            },
            "AnalysisStatistics": {
                "type": "object",
                "properties": {
                    "protocol_breakdown": { "type": "object" },
                    "top_talkers": { "type": "array" },
                    "top_ports": { "type": "array" },
                    "total_findings": { "type": "integer" },
                    "total_artifacts": { "type": "integer" },
                    "total_credentials": { "type": "integer" },
                    "analysis_duration_ms": { "type": "integer" }
                },
                "required": ["total_findings", "total_artifacts", "total_credentials", "analysis_duration_ms"]
            }
        }
    }))
    .expect("schema serialization should not fail");

    schema
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_generates_valid_json() {
        let schema = generate_report_schema();
        let parsed: serde_json::Value = serde_json::from_str(&schema).unwrap();
        assert_eq!(parsed["title"], "WireHunt Report v1");
        assert!(parsed["$defs"]["Finding"].is_object());
        assert!(parsed["$defs"]["EvidenceRef"].is_object());
    }
}
