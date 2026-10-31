import argparse
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .anomaly import AnomalyDetector
from .config import load_config
from .device_profile import DeviceProfiler
from .dns_parser import DNSQuery
from .dns_proxy import DNSDecision, DNSProxy
from .entropy import shannon_entropy
from .online_model import load_model
from .online_nb import load_nb_model
from .statistical_model import load_statistical_model, save_statistical_model
from .trm_adapter import load_trm
from .enforcement import update_hosts_blocklist


@dataclass
class GuardState:
    queries_seen: int = 0


class Guard:
    def __init__(self, config_path: str, model_path: str | None) -> None:
        self.config = load_config(config_path)
        self.profiler = DeviceProfiler()
        self.detector = AnomalyDetector(self.config)
        self.trm_model = load_trm(self.config.trm_weights)
        self.online_model = None
        self.statistical_model = None
        self.nb_model = None
        self.model_path = model_path
        if model_path and self.config.model_type == "online_logistic":
            self.online_model = load_model(model_path, self.config.learning_rate)
        elif model_path and self.config.model_type == "statistical":
            self.statistical_model = load_statistical_model(model_path, self.config.zscore_threshold)
        elif model_path and self.config.model_type == "gaussian_nb":
            self.nb_model = load_nb_model(model_path)
        self.log_path = Path(self.config.guard_log_path)
        self.blocklist_path = Path(self.config.blocklist_path)
        self.blocked_domains = self._load_blocklist()
        self.state = GuardState()

    def _load_blocklist(self) -> set[str]:
        if not self.blocklist_path.exists():
            return set()
        domains = set()
        for line in self.blocklist_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domains.add(line.lower())
        return domains

    def _save_blocklist(self) -> None:
        lines = ["# AI Firewall TRM blocklist", f"# Updated {datetime.utcnow().isoformat()}Z"]
        lines.extend(sorted(self.blocked_domains))
        self.blocklist_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _log_query(self, query: DNSQuery) -> None:
        line = (
            f"{query.timestamp.strftime('%b %d %H:%M:%S')} ai-firewall dns-proxy[{self.state.queries_seen}]: "
            f"query[{query.qtype}] {query.domain} from {query.client}"
        )
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def _score(self, query: DNSQuery) -> tuple[bool, float]:
        tld = query.domain.split(".")[-1].lower() if "." in query.domain else ""
        entropy = shannon_entropy(query.domain)
        is_new_tld = self.profiler.update(query.client, tld, entropy)
        flags, features = self.detector.score(query, is_new_tld, entropy=entropy, tld=tld)
        if self.online_model:
            score = self.online_model.predict_proba(features)
            decision = score >= self.config.decision_threshold
        elif self.nb_model:
            score = self.nb_model.predict_proba(features)
            decision = score >= self.config.decision_threshold
        elif self.statistical_model:
            self.statistical_model.update(features)
            score = self.statistical_model.score(features, query.domain)
            decision = score >= self.config.decision_threshold
        else:
            result = self.trm_model.infer(features)
            score = result.score
            decision = result.decision == "flag"
        return decision, score

    def handle_query(self, client_ip: str, domain: str, qtype: str) -> DNSDecision:
        self.state.queries_seen += 1
        if not domain:
            return DNSDecision(block=False)
        if domain in self.blocked_domains:
            return DNSDecision(block=True, reason="blocklist")
        query = DNSQuery(
            timestamp=datetime.utcnow(),
            client=client_ip,
            domain=domain,
            qtype=qtype,
            raw="",
        )
        self._log_query(query)
        should_block, score = self._score(query)
        if should_block and self.config.enforce_dns:
            self.blocked_domains.add(domain)
            self._save_blocklist()
            if self.config.enforce_hosts:
                try:
                    update_hosts_blocklist(list(self.blocked_domains), self.config.hosts_path)
                except OSError:
                    pass
            if self.statistical_model and self.model_path and self.state.queries_seen % 250 == 0:
                save_statistical_model(self.model_path, self.statistical_model)
            return DNSDecision(block=True, reason=f"score={score:.2f}")
        return DNSDecision(block=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="AI Firewall real-time guard")
    parser.add_argument("--config", required=True, help="Path to config JSON")
    parser.add_argument("--model", help="Path to model JSON")
    parser.add_argument("--listen-host", help="Override listen host")
    parser.add_argument("--listen-port", type=int, help="Override listen port")
    parser.add_argument("--upstream", help="Override upstream DNS")
    args = parser.parse_args()

    guard = Guard(args.config, args.model)
    listen_host = args.listen_host or guard.config.dns_listen_host
    listen_port = args.listen_port or guard.config.dns_listen_port
    upstream = args.upstream or guard.config.dns_upstream

    proxy = DNSProxy(
        listen_host=listen_host,
        listen_port=listen_port,
        upstream=upstream,
        timeout_seconds=guard.config.dns_timeout_seconds,
        on_query=guard.handle_query,
        block_response=guard.config.dns_block_response,
    )
    proxy.serve_forever()


if __name__ == "__main__":
    main()
