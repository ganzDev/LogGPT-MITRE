import json
from attackcti import attack_client
import logging
import pandas as pd
import csv
import os
from collections import Counter

def export_mitre_alerts(alerts, output_path):
    columns = [
        "Window ID",
        "True Label",
        "Predicted Label",
        "Alert Type",
        "Event Sequence",
        "Technique IDs",
        "Technique Names",
        "Tactics",
        "Data Sources",
        "Reasons",
    ]

    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()

        for alert in alerts:
            writer.writerow(alert)

    print(f"Exported MITRE alerts to {output_path}")


MITRE_SUMMARY_COLUMNS = [
    "Run ID",
    "True Positives",
    "False Positives",
    "Total Predicted Anomaly Alerts",
    "MITRE-Mapped Alerts",
    "No MITRE Mapping Alerts",
    "Technique Counts",
    "Tactic Counts",
]


def _next_run_id(path):
    if not os.path.exists(path):
        return 1

    with open(path, "r", newline="") as f:
        rows = list(csv.reader(f))

    if len(rows) <= 1:
        return 1

    return len(rows)


def _format_counter(counter):
    if not counter:
        return ""

    return "; ".join(
        f"{key} ({count})"
        for key, count in sorted(counter.items())
    )


def append_mitre_summary(label, y_pred, alerts, output_path):
    label = list(label)
    y_pred = list(y_pred)

    true_positives = sum(
        1 for true, pred in zip(label, y_pred)
        if true == 1 and pred == 1
    )

    false_positives = sum(
        1 for true, pred in zip(label, y_pred)
        if true == 0 and pred == 1
    )

    total_predicted_alerts = sum(
        1 for pred in y_pred
        if pred == 1
    )

    technique_counter = Counter()
    tactic_counter = Counter()

    mitre_mapped = 0
    mitre_unmapped = 0

    for alert in alerts:
        technique_ids = str(alert.get("Technique IDs", "")).strip()
        tactics = str(alert.get("Tactics", "")).strip()

        if technique_ids and technique_ids != "No MITRE Mapping":
            mitre_mapped += 1

            for technique_id in technique_ids.split(";"):
                technique_id = technique_id.strip()
                if technique_id:
                    technique_counter[technique_id] += 1
        else:
            mitre_unmapped += 1

        if tactics:
            for tactic in tactics.split(";"):
                tactic = tactic.strip()
                if tactic:
                    tactic_counter[tactic] += 1

    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    file_exists = os.path.exists(output_path)

    row = {
        "Run ID": _next_run_id(output_path),
        "True Positives": true_positives,
        "False Positives": false_positives,
        "Total Predicted Anomaly Alerts": total_predicted_alerts,
        "MITRE-Mapped Alerts": mitre_mapped,
        "No MITRE Mapping Alerts": mitre_unmapped,
        "Technique Counts": _format_counter(technique_counter),
        "Tactic Counts": _format_counter(tactic_counter),
    }

    with open(output_path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=MITRE_SUMMARY_COLUMNS)

        if not file_exists:
            writer.writeheader()

        writer.writerow(row)

    print(f"Appended MITRE summary to {output_path}")



logging.getLogger('taxii2client').setLevel(logging.CRITICAL)


LINUX_TOKEN_TO_TECHNIQUE_IDS = {
    "AUTH_FAIL": ["T1110"],
    "AUTH_FAIL_USER": ["T1110"],
    "ROOT_AUTH_FAIL": ["T1110", "T1078"],
    "UNKNOWN_USER": ["T1110"],
    "UNKNOWN_USER_TIMEOUT": ["T1110"],
    "KERBEROS_AUTH_FAIL": ["T1110"],
    "FTP_CONNECTION": ["T1133"],
    "FTP_PEER_DISCONNECT": ["T1133"],
    "EXPLOIT_PAYLOAD_ATTEMPT": ["T1190"],
    "SSHD_MAX_RETRIES_EXCEEDED": ["T1110"],
    "FAILED_LOGIN": ["T1110"],
    "BAD_USERNAME": ["T1110"],
    "PORT_SCAN_SUSPECTED": ["T1046"],
}


MITRE_FALLBACK = {
    "T1078": {
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "tactics": [
            "defense-evasion",
            "persistence",
            "privilege-escalation",
            "initial-access",
        ],
        "data_sources": ["User Account", "Logon Session"],
    },
    "T1110": {
        "technique_id": "T1110",
        "name": "Brute Force",
        "tactics": ["credential-access"],
        "data_sources": ["Logon Session", "User Account"],
    },
    "T1133": {
        "technique_id": "T1133",
        "name": "External Remote Services",
        "tactics": ["initial-access", "persistence"],
        "data_sources": ["Logon Session", "Network Traffic"],
    },
    "T1190": {
        "technique_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactics": ["initial-access"],
        "data_sources": ["Application Log", "Network Traffic"],
    },
    "T1046": {
        "technique_id": "T1046",
        "name": "Network Service Discovery",
        "tactics": ["discovery"],
        "data_sources": ["Network Traffic"],
    },
}


class MitreMapper:
    def __init__(self):
        self.lift = attack_client()
        self.technique_lookup = self._build_technique_lookup()


    def _build_technique_lookup(self):
        lookup = {}

        try:
            techniques = self.lift.get_enterprise_techniques()
        except Exception:
            techniques = self.lift.get_techniques()

        # exp_techniques = []
        # for t in techniques:
        #     exp_techniques.append(json.loads(t.serialize()))
        # df = pandas.json_normalize(exp_techniques)
        # df.to_csv('all_techniques_stix.csv', index=False)

        for technique in techniques:
            technique_id = self._get_external_id(technique)

            if technique_id:
                lookup[technique_id] = {
                    "technique_id": technique_id,
                    "name": getattr(technique, "name", ""),
                    "description": getattr(technique, "description", ""),
                    "platforms": getattr(technique, "x_mitre_platforms", []),
                    "data_sources": getattr(technique, "x_mitre_data_sources", []),
                    "tactics": self._get_tactics(technique),
                }

        return lookup

    def _get_external_id(self, technique):
        for ref in getattr(technique, "external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")
        return None

    def _get_tactics(self, technique):
        tactics = []

        for phase in getattr(technique, "kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase.get("phase_name"))

        return tactics

    def _get_technique_metadata(self, technique_id):
        technique = self.technique_lookup.get(technique_id)

        if technique is None:
            technique = MITRE_FALLBACK.get(
                technique_id,
                {
                    "technique_id": technique_id,
                    "name": "",
                    "description": "",
                    "platforms": [],
                    "data_sources": [],
                    "tactics": [],
                },
            )

        return technique

    def map_tokens_to_techniques(self, tokens):
        technique_ids = set()

        for token in tokens:
            for technique_id in LINUX_TOKEN_TO_TECHNIQUE_IDS.get(token, []):
                technique_ids.add(technique_id)

        return [
            self._get_technique_metadata(technique_id)
            for technique_id in sorted(technique_ids)
        ]

    def map_linux_window(self, tokens):
        findings = []

        auth_fails = (
            tokens.count("AUTH_FAIL")
            + tokens.count("AUTH_FAIL_USER")
            + tokens.count("ROOT_AUTH_FAIL")
            + tokens.count("KERBEROS_AUTH_FAIL")
            + tokens.count("FAILED_LOGIN")
            + tokens.count("BAD_USERNAME")
        )

        unknown_users = (
            tokens.count("UNKNOWN_USER")
            + tokens.count("UNKNOWN_USER_TIMEOUT")
        )

        ftp_connections = tokens.count("FTP_CONNECTION")

        if auth_fails >= 5 or unknown_users >= 3:
            findings.append(
                self._finding(
                    "T1110",
                    f"Window contains {auth_fails} authentication failures and {unknown_users} unknown-user events.",
                )
            )

        if "ROOT_AUTH_FAIL" in tokens:
            findings.append(
                self._finding(
                    "T1078",
                    "Root account authentication activity was observed.",
                )
            )

        if ftp_connections >= 10:
            findings.append(
                self._finding(
                    "T1133",
                    f"Window contains {ftp_connections} FTP connection events.",
                )
            )

        if "EXPLOIT_PAYLOAD_ATTEMPT" in tokens:
            findings.append(
                self._finding(
                    "T1190",
                    "Exploit-like payload was observed in the log sequence.",
                )
            )

        if "PORT_SCAN_SUSPECTED" in tokens:
            findings.append(
                self._finding(
                    "T1046",
                    "Port scanning behavior was observed.",
                )
            )

        for technique in self.map_tokens_to_techniques(tokens):
            findings.append(
                {
                    "technique_id": technique.get("technique_id"),
                    "name": technique.get("name", ""),
                    "tactics": technique.get("tactics", []),
                    "data_sources": technique.get("data_sources", []),
                    "reason": "Mapped from Linux semantic token.",
                }
            )

        return self._deduplicate_findings(findings)

    def _finding(self, technique_id, reason):
        technique = self._get_technique_metadata(technique_id)

        return {
            "technique_id": technique_id,
            "name": technique.get("name", ""),
            "tactics": technique.get("tactics", []),
            "data_sources": technique.get("data_sources", []),
            "reason": reason,
        }

    def _deduplicate_findings(self, findings):
        deduped = {}

        for finding in findings:
            technique_id = finding["technique_id"]

            if technique_id not in deduped:
                deduped[technique_id] = finding
            else:
                old_reason = deduped[technique_id].get("reason", "")
                new_reason = finding.get("reason", "")

                if new_reason and new_reason not in old_reason:
                    deduped[technique_id]["reason"] = (
                        old_reason + " " + new_reason
                    ).strip()

        return list(deduped.values())