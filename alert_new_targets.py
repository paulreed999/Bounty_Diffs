#!/usr/bin/env python3
import os
import sys
import json
import time
import hashlib
import logging
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from typing import Dict, List, Tuple, Any, Set


# Configuration
CONFIG_PATH = "/home/mastermind/configs/settings.yaml"
OUTPUT_DIR = "/home/mastermind/Bounty_Diffs"
LOGS_DIR = os.path.join(OUTPUT_DIR, "logs")
LOG_FILE = os.path.join(LOGS_DIR, "bounty_monitor.log")

# Data sources (raw JSON files in arkadiyt/bounty-targets-data)
RAW_BASE = (
    "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data"
)
PLATFORM_FILES = {
    "HACKERONE": "hackerone_data.json",
    "BUGCROWD": "bugcrowd_data.json",
    "INTIGRITI": "intigriti_data.json",
    "YESWEHACK": "yeswehack_data.json",
}


def ensure_dirs() -> None:
    os.makedirs(LOGS_DIR, exist_ok=True)


def setup_logger() -> logging.Logger:
    logger = logging.getLogger("bounty_monitor")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        fmt="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fh = logging.FileHandler(LOG_FILE)
    fh.setLevel(logging.INFO)
    fh.setFormatter(formatter)
    if not logger.handlers:
        logger.addHandler(fh)
    return logger


def read_settings_yaml(path: str) -> Dict[str, str]:
    """
    Minimal YAML reader for simple key: value pairs.
    Avoids external dependencies (PyYAML).
    """
    settings: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line_stripped = line.strip()
                if not line_stripped or line_stripped.startswith("#"):
                    continue
                if ":" in line_stripped:
                    key, val = line_stripped.split(":", 1)
                    settings[key.strip()] = val.strip().strip('"\'')
    except FileNotFoundError:
        pass
    return settings


def http_get_json(url: str, timeout: int) -> Any:
    req = Request(url, headers={"User-Agent": "BountyDiffsMonitor/1.0"})
    with urlopen(req, timeout=timeout) as resp:
        data = resp.read()
        return json.loads(data.decode("utf-8"))


def load_previous_snapshot(path: str) -> Any:
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_snapshot(path: str, obj: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))


def extract_targets_and_rewards(platform: str, data_obj: Any) -> Tuple[Set[str], Set[str]]:
    """
    Extract target URLs/domains from platform data and identify which offer rewards.
    Returns (all_targets, rewarded_targets)
    """
    all_targets: Set[str] = set()
    rewarded: Set[str] = set()

    def mark(target: str, has_reward: bool) -> None:
        if not target or not target.strip():
            return
        target = target.strip()
        all_targets.add(target)
        if has_reward:
            rewarded.add(target)

    try:
        programs = data_obj if isinstance(data_obj, list) else []

        for program in programs:
            if not isinstance(program, dict):
                continue

            # Program-level bounty info
            program_offers_bounty = bool(program.get("offers_bounties", False))
            program_name = program.get("name") or program.get("handle", "Unknown")

            # Extract targets from in_scope
            targets_data = program.get("targets", {})
            in_scope = targets_data.get("in_scope", []) if isinstance(targets_data, dict) else []

            for asset in in_scope:
                if not isinstance(asset, dict):
                    continue

                # Get the actual target URL/domain
                target = asset.get("asset_identifier", "").strip()
                if not target:
                    continue

                # Check if this specific target offers bounty
                target_eligible = asset.get("eligible_for_bounty", False)
                has_reward = target_eligible or (not target_eligible and program_offers_bounty)

                # Format: "Program Name (type) - target_url"
                asset_type = asset.get("asset_type", "other").lower()
                display_target = f"{program_name} ({asset_type}) - {target}"
                
                mark(display_target, has_reward)

    except Exception as e:
        # Log but don't fail the entire run
        print(f"Warning: Error extracting targets from {platform}: {e}")

    return all_targets, rewarded


def compute_numbered_prefix(dir_path: str) -> str:
    existing = [f for f in os.listdir(dir_path) if f.endswith(".txt") and f[:4].isdigit()]
    if not existing:
        return "0001"
    max_n = 0
    for f in existing:
        try:
            n = int(f[:4])
            if n > max_n:
                max_n = n
        except ValueError:
            continue
    return f"{max_n + 1:04d}"


def write_report(prefix: str, new_lines: List[str], removed_lines: List[str]) -> None:
    new_path = os.path.join(OUTPUT_DIR, f"{prefix}_new_targets.txt")
    rem_path = os.path.join(OUTPUT_DIR, f"{prefix}_removed_targets.txt")
    with open(new_path, "w", encoding="utf-8") as f:
        f.write("\n".join(new_lines) + ("\n" if new_lines else ""))
    with open(rem_path, "w", encoding="utf-8") as f:
        f.write("\n".join(removed_lines) + ("\n" if removed_lines else ""))


def send_slack(webhook_url: str, text: str, timeout: int) -> bool:
    if not webhook_url:
        return False
    try:
        body = json.dumps({"text": text}).encode("utf-8")
        req = Request(
            webhook_url,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "BountyDiffsMonitor/1.0"},
        )
        with urlopen(req, timeout=timeout) as resp:
            _ = resp.read()
        return True
    except Exception:
        return False


def main() -> int:
    ensure_dirs()
    logger = setup_logger()
    logger.info("Starting bounty target monitor...")

    # Load settings
    settings = read_settings_yaml(CONFIG_PATH)
    timeout = int(settings.get("request_timeout_seconds", "15") or 15)
    slack_webhook = (
        settings.get("slack_webhook_url")
        or settings.get("slack_webhook")
        or ""
    )

    # Fetch current data and compare to snapshots
    any_changes = False
    total_new = 0
    total_removed = 0
    new_report_lines: List[str] = []
    removed_report_lines: List[str] = []

    try:
        for platform, filename in PLATFORM_FILES.items():
            url = f"{RAW_BASE}/{filename}"
            snapshot_path = os.path.join(OUTPUT_DIR, filename)

            try:
                current_obj = http_get_json(url, timeout)
            except (HTTPError, URLError, TimeoutError) as e:
                logger.info(f"Failed to fetch {platform} data: {e}")
                continue

            prev_obj = load_previous_snapshot(snapshot_path)
            save_snapshot(snapshot_path, current_obj)

            # On first run, seed only
            if prev_obj is None:
                continue

            curr_targets, curr_rewarded = extract_targets_and_rewards(platform, current_obj)
            prev_targets, prev_rewarded = extract_targets_and_rewards(platform, prev_obj)

            added = sorted(curr_targets - prev_targets)
            removed = sorted(prev_targets - curr_targets)

            if added:
                any_changes = True
                logger.info(f"🎯 {platform}: {len(added)} new targets found")

                # Rewards break-down
                with_rewards = [t for t in added if t in curr_rewarded]
                without_rewards = [t for t in added if t not in curr_rewarded]

                if with_rewards:
                    logger.info(f"💰 {len(with_rewards)} targets WITH REWARDS:")
                    for t in with_rewards[:50]:
                        logger.info(f"   🔥 {t}")
                if without_rewards:
                    logger.info(f"❌ {len(without_rewards)} targets WITHOUT REWARDS:")
                    sample = without_rewards[:50]
                    for idx, t in enumerate(sample):
                        if idx < 2 or len(sample) <= 3:
                            logger.info(f"   📝 {t}")
                        elif idx == 2 and len(without_rewards) > len(sample):
                            remaining = len(without_rewards) - len(sample)
                            logger.info(f"   ... and {remaining} more non-rewarded targets")
                            break

                total_new += len(added)
                # Append to text report
                new_report_lines.append(f"[{platform}] +{len(added)} new")
                for t in added:
                    new_report_lines.append(f" + {t}")

            if removed:
                any_changes = True
                logger.info(f"🗑️ {platform}: {len(removed)} targets removed")
                total_removed += len(removed)
                removed_report_lines.append(f"[{platform}] -{len(removed)} removed")
                for t in removed:
                    removed_report_lines.append(f" - {t}")

        logger.info("Repository updated successfully")

        if any_changes:
            if new_report_lines or removed_report_lines:
                prefix = compute_numbered_prefix(OUTPUT_DIR)
                write_report(prefix, new_report_lines, removed_report_lines)

            if slack_webhook:
                summary = f"📊 Total new targets: {total_new}"
                if total_removed:
                    summary += f" | 🗑️ Total removed targets: {total_removed}"
                ok = send_slack(slack_webhook, summary, timeout)
                if ok:
                    logger.info("Slack alert sent successfully")
        else:
            logger.info("✅ No changes detected across all platforms")

        logger.info("Bounty target monitor completed")
        print("Success: Bounty target monitor completed")
        return 0

    except Exception as ex:
        logger.info(f"Run failed: {ex}")
        print(f"Failure: {ex}")
        return 1


if __name__ == "__main__":
    sys.exit(main())


