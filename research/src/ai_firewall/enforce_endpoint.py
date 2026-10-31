import argparse
from .config import load_config
from .endpoint import analyze_endpoint, load_endpoint_snapshot
from .enforcement import ensure_firewall_block, defender_scan_file


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def main() -> None:
    parser = argparse.ArgumentParser(description="AI Firewall endpoint enforcement")
    parser.add_argument("--config", required=True, help="Path to config JSON")
    parser.add_argument("--snapshot", required=True, help="Path to endpoint snapshot JSON")
    parser.add_argument("--baseline", help="Path to baseline endpoint snapshot JSON")
    parser.add_argument("--min-severity", default="high", choices=["low", "medium", "high"])
    args = parser.parse_args()

    config = load_config(args.config)
    snapshot = load_endpoint_snapshot(args.snapshot)
    baseline = load_endpoint_snapshot(args.baseline) if args.baseline else None
    findings = analyze_endpoint(snapshot, baseline=baseline)

    threshold = SEVERITY_RANK.get(args.min_severity, 3)
    enforce_types = {"process_path", "startup_command", "task_action"}
    for finding in findings:
        severity = SEVERITY_RANK.get(finding.severity, 1)
        if severity < threshold:
            continue
        if not finding.artifact_path or finding.artifact_type not in enforce_types:
            continue
        result = ensure_firewall_block(finding.artifact_path, config.firewall_rule_prefix)
        print(f"FIREWALL {finding.artifact_path} => {result.ok} {result.message}")
        if config.defender_scan:
            scan_result = defender_scan_file(finding.artifact_path)
            print(f"DEFENDER {finding.artifact_path} => {scan_result.ok} {scan_result.message}")


if __name__ == "__main__":
    main()
