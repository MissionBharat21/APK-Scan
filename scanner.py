"""scanner.py - APK Sentinel: main CLI entry point."""
import argparse
import os
import sys
import time
import traceback
from datetime import datetime
from typing import Dict, List, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from hashes import HashCalculator
from analyzer import APKAnalyzer, APKAnalysisError
from permissions import PermissionAnalyzer
from stringscan import StringScanner
from signatures import SignatureScanner
from risk import RiskEngine
from report import ReportGenerator
from utils import setup_logging, load_config, validate_apk_file, find_apks_in_folder
from monitor import DeviceInspector, BehaviorHistory
from realtime import RealtimeGuard
from notifier import MessageBuilder, AlertDispatcher
from cert_blocklist import CertBlocklist, TrustAllowlist
from alert_throttle import AlertThrottle

console = Console()


class APKSentinel:
    """Orchestrates a full static scan of a single APK file."""

    def __init__(self, config: Dict, logger) -> None:
        self.config = config
        self.logger = logger
        self.cert_blocklist = CertBlocklist()
        self.sig_scanner = SignatureScanner(config.get("yara", {}).get("rules_dir", "rules"))

    def scan(self, apk_path: str) -> Optional[Dict]:
        error = validate_apk_file(apk_path, self.config.get("max_file_size_gb", 3))
        if error:
            console.print(f"[bold red]Error:[/bold red] {error}")
            self.logger.error(f"Validation failed for {apk_path}: {error}")
            return None

        result: Dict = {"file_path": apk_path}

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TimeElapsedColumn(), console=console,
        ) as progress:
            task = progress.add_task("Calculating hashes...", total=8)

            result["hashes"] = HashCalculator(apk_path).calculate_all()
            progress.advance(task)

            try:
                progress.update(task, description="Parsing APK structure...")
                analyzer = APKAnalyzer(apk_path)
            except APKAnalysisError as exc:
                console.print(f"[bold red]Error:[/bold red] {exc}")
                self.logger.error(f"Analysis failed for {apk_path}: {exc}")
                return None

            result["basic_info"] = analyzer.get_basic_info()
            progress.advance(task)

            progress.update(task, description="Reading permissions...")
            raw_permissions = analyzer.get_permissions()
            perm_analyzer = PermissionAnalyzer(raw_permissions)
            result["permissions"] = perm_analyzer.summary()
            result["permissions"]["all_permissions"] = sorted(raw_permissions)
            progress.advance(task)

            progress.update(task, description="Enumerating components & libraries...")
            result["components"] = analyzer.get_components()
            result["native_libraries"] = analyzer.get_native_libraries()
            result["dex_count"] = analyzer.get_dex_count()
            result["certificate"] = analyzer.get_certificate_info()
            progress.advance(task)

            progress.update(task, description="Checking certificate reputation...")
            if result["certificate"].get("signed"):
                result["cert_blocklisted"] = self.cert_blocklist.is_blocked(result["certificate"])
                result["cert_shared_count"] = self.cert_blocklist.record_seen(
                    result["certificate"], result["basic_info"]["package_name"]
                )
            else:
                result["cert_blocklisted"] = False
                result["cert_shared_count"] = 0
            progress.advance(task)

            progress.update(task, description="Checking manifest configuration...")
            result["manifest_flags"] = analyzer.get_manifest_flags(result["basic_info"])
            progress.advance(task)

            progress.update(task, description="Scanning strings, URLs & YARA signatures...")
            scanner = StringScanner(apk_path)
            result["strings"] = scanner.scan()
            class_names = analyzer.get_dex_class_names()
            result["obfuscation"] = scanner.detect_obfuscation(class_names)
            result["yara"] = self.sig_scanner.scan_file(apk_path)
            progress.advance(task)

            progress.update(task, description="Calculating risk score...")
            score, status, breakdown = RiskEngine(result).calculate()
            result["risk"] = {"score": score, "status": status, "breakdown": breakdown}
            progress.advance(task)

        self.logger.info(f"Scanned {apk_path}: risk={score} status={status}")
        return result


def print_summary(result: Dict) -> None:
    basic = result["basic_info"]
    perms = result["permissions"]
    strings = result["strings"]
    risk = result["risk"]
    cert = result["certificate"]
    yara_result = result.get("yara", {})
    manifest = result.get("manifest_flags", {})

    status = risk["status"]
    status_color = {"HIGH RISK": "red", "MEDIUM RISK": "yellow", "LOW RISK": "green"}.get(status, "white")

    console.print()
    console.print("=" * 40, style="bold cyan")
    console.print("APK Sentinel", style="bold cyan")
    console.print("=" * 40, style="bold cyan")
    console.print()

    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()
    table.add_row("Package:", basic["package_name"])
    table.add_row("Version:", f"{basic['version_name']} ({basic['version_code']})")
    table.add_row("SHA256:", result["hashes"]["sha256"])
    table.add_row("Permissions:", str(perms["total_permissions"]))
    table.add_row("Dangerous Permissions:", str(perms["dangerous_count"]))
    table.add_row("Native Libraries:", str(len(result["native_libraries"])))
    table.add_row("Certificate:", "Signed" if cert.get("signed") else "Unsigned")
    table.add_row("URLs Found:", str(len(strings["urls"])))
    if yara_result.get("available"):
        table.add_row("YARA Matches:", str(len(yara_result.get("matches", []))))
    table.add_row("Manifest Flags:", str(manifest.get("flag_count", 0)))
    table.add_row("Risk Score:", f"{risk['score']}/100")
    table.add_row("Status:", f"[{status_color}]{status}[/{status_color}]")
    console.print(table)
    console.print()
    console.print("=" * 40, style="bold cyan")

    if perms["dangerous_permissions"]:
        console.print("\n[bold]Dangerous Permissions:[/bold]")
        for p in perms["dangerous_permissions"]:
            console.print(f"  [red]•[/red] {p}")

    if perms["suspicious_combinations"]:
        console.print("\n[bold]Suspicious Combinations:[/bold]")
        for c in perms["suspicious_combinations"]:
            console.print(f"  [yellow]⚠[/yellow] {c}")

    if strings["suspicious_strings"]:
        console.print("\n[bold]Suspicious Strings:[/bold]")
        for s in strings["suspicious_strings"]:
            console.print(f"  [magenta]•[/magenta] {s}")

    if yara_result.get("matches"):
        console.print("\n[bold]YARA Signature Matches:[/bold]")
        for m in yara_result["matches"]:
            console.print(f"  [red]•[/red] {m['rule']} — {m['description']} ({m['severity']})")
    elif not yara_result.get("available"):
        console.print(f"\n[dim]YARA scanning unavailable: {yara_result.get('reason')}[/dim]")

    if manifest.get("flags"):
        console.print("\n[bold]Manifest Flags:[/bold]")
        for f in manifest["flags"]:
            console.print(f"  [yellow]⚠[/yellow] {f['detail']} ({f['severity']})")

    if result.get("cert_blocklisted"):
        console.print("\n[bold red]Certificate is on your local blocklist![/bold red]")
    elif result.get("cert_shared_count", 0) > 3:
        console.print(f"\n[yellow]Note:[/yellow] This certificate has signed "
                       f"{result['cert_shared_count']} different packages you've scanned.")

    console.print()


def _generate_reports(result: Dict, config: Dict) -> None:
    gen = ReportGenerator(result, output_dir=config.get("reports_dir", "reports"))
    json_path = gen.to_json()
    html_path = gen.to_html()
    txt_path = gen.to_txt()
    csv_path = gen.to_csv()
    console.print(Panel(
        f"[green]JSON:[/green] {json_path}\n[green]HTML:[/green] {html_path}\n"
        f"[green]TXT:[/green]  {txt_path}\n[green]CSV:[/green]  {csv_path}",
        title="Reports Generated", border_style="green",
    ))


def _print_folder_summary(results: List[Dict]) -> None:
    if not results:
        return
    table = Table(title="Scan Summary")
    table.add_column("Package")
    table.add_column("Risk Score")
    table.add_column("Status")
    for r in results:
        status = r["risk"]["status"]
        color = {"HIGH RISK": "red", "MEDIUM RISK": "yellow", "LOW RISK": "green"}.get(status, "white")
        table.add_row(r["basic_info"]["package_name"], f"{r['risk']['score']}/100", f"[{color}]{status}[/{color}]")
    console.print(table)


def _top_risk_reasons(result: Dict) -> List[str]:
    reasons = []
    perms = result["permissions"]
    reasons += perms.get("suspicious_combinations", [])[:3]
    reasons += [f"Dangerous permission: {p}" for p in perms.get("dangerous_permissions", [])[:3]]
    strings = result["strings"]
    if strings.get("suspicious_strings"):
        reasons.append(f"Suspicious strings: {', '.join(strings['suspicious_strings'][:5])}")
    if result.get("obfuscation", {}).get("obfuscated"):
        reasons.append("Code appears obfuscated")
    cert = result.get("certificate", {})
    if not cert.get("signed", True):
        reasons.append("APK is unsigned")
    elif cert.get("self_signed"):
        reasons.append("Certificate is self-signed")
    for m in result.get("yara", {}).get("matches", [])[:3]:
        reasons.append(f"YARA: {m['rule']} ({m['description']})")
    for f in result.get("manifest_flags", {}).get("flags", [])[:3]:
        reasons.append(f"Manifest: {f['detail']}")
    return reasons[:10]


def _print_dispatch_result(sent: Dict[str, bool]) -> None:
    if not sent:
        return
    lines = [f"{'✓' if ok else '✗'} {channel}" for channel, ok in sent.items()]
    console.print(Panel("\n".join(lines), title="Alert Dispatched", border_style="cyan"))


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def cmd_scan(args, config, logger) -> None:
    sentinel = APKSentinel(config, logger)
    result = sentinel.scan(args.apk_file)
    if result is None:
        sys.exit(1)
    print_summary(result)
    if args.save_report:
        _generate_reports(result, config)

    if result["risk"]["status"] in ("HIGH RISK", "MEDIUM RISK"):
        message = MessageBuilder.from_scan_result(
            package=result["basic_info"]["package_name"],
            risk_score=result["risk"]["score"], status=result["risk"]["status"],
            top_reasons=_top_risk_reasons(result),
        )
        dispatcher = AlertDispatcher(config, logger)
        _print_dispatch_result(dispatcher.dispatch(message))


def cmd_scan_folder(args, config, logger) -> None:
    apks = find_apks_in_folder(args.folder)
    if not apks:
        console.print(f"[yellow]No .apk files found in {args.folder}[/yellow]")
        return

    console.print(f"[bold cyan]Found {len(apks)} APK(s) to scan[/bold cyan]\n")
    sentinel = APKSentinel(config, logger)
    dispatcher = AlertDispatcher(config, logger)
    results: List[Dict] = []

    for apk_path in apks:
        console.print(f"[bold]Scanning:[/bold] {apk_path}")
        result = sentinel.scan(apk_path)
        if result:
            print_summary(result)
            results.append(result)
            if args.save_report:
                _generate_reports(result, config)
            if result["risk"]["status"] in ("HIGH RISK", "MEDIUM RISK"):
                message = MessageBuilder.from_scan_result(
                    package=result["basic_info"]["package_name"],
                    risk_score=result["risk"]["score"], status=result["risk"]["status"],
                    top_reasons=_top_risk_reasons(result),
                )
                dispatcher.dispatch(message)

    _print_folder_summary(results)


def cmd_report(args, config, logger) -> None:
    sentinel = APKSentinel(config, logger)
    result = sentinel.scan(args.apk_file)
    if result is None:
        sys.exit(1)
    print_summary(result)
    _generate_reports(result, config)


def cmd_diff(args, config, logger) -> None:
    """Re-scan an APK and diff it against the last report generated for the same package."""
    sentinel = APKSentinel(config, logger)
    result = sentinel.scan(args.apk_file)
    if result is None:
        sys.exit(1)

    reports_dir = config.get("reports_dir", "reports")
    pkg = result["basic_info"]["package_name"].replace(".", "_")
    candidates = sorted(
        [f for f in os.listdir(reports_dir) if f.startswith(pkg) and f.endswith("_report.json")]
    ) if os.path.isdir(reports_dir) else []

    if not candidates:
        console.print("[yellow]No previous report found for this package — saving this as the baseline.[/yellow]")
        _generate_reports(result, config)
        return

    import json
    with open(os.path.join(reports_dir, candidates[-1]), "r", encoding="utf-8") as f:
        prev = json.load(f)

    changes = []
    if prev.get("hashes", {}).get("sha256") != result["hashes"]["sha256"]:
        changes.append("APK file hash changed (app was updated)")
    prev_perms = set(prev.get("permissions", {}).get("all_permissions", []))
    new_perms = set(result["permissions"]["all_permissions"])
    added = new_perms - prev_perms
    removed = prev_perms - new_perms
    if added:
        changes.append(f"New permissions added: {', '.join(sorted(added))}")
    if removed:
        changes.append(f"Permissions removed: {', '.join(sorted(removed))}")
    if prev.get("risk", {}).get("score") != result["risk"]["score"]:
        changes.append(f"Risk score changed: {prev.get('risk', {}).get('score')} -> {result['risk']['score']}")

    if changes:
        console.print(Panel("\n".join(f"• {c}" for c in changes),
                             title="Changes since last scan", border_style="yellow"))
    else:
        console.print("[green]No meaningful changes since the last scan.[/green]")

    _generate_reports(result, config)


def cmd_watch(args, config, logger) -> None:
    package = args.package
    interval = args.interval or config.get("watch_interval_seconds", 3600)
    history = BehaviorHistory(package, store_dir=os.path.join(config.get("reports_dir", "reports"), "monitor"))
    inspector = DeviceInspector(package)
    dispatcher = AlertDispatcher(config, logger)
    allowlist = TrustAllowlist()
    throttle = AlertThrottle(config.get("alert_cooldown_seconds", 1800))

    if allowlist.is_trusted_package(package):
        console.print(f"[dim]{package} is in your trust allowlist — alerts will still log but notify less loudly.[/dim]")

    console.print(f"[bold cyan]Watching {package} every {interval}s. Ctrl+C to stop.[/bold cyan]")

    try:
        while True:
            snapshot = inspector.snapshot()
            result = history.diff_latest(snapshot)

            if not snapshot.capabilities_used:
                console.print(
                    "[yellow]Warning:[/yellow] no observable signals available this cycle "
                    "(package not found, or no root/ADB/logcat access)."
                )
            elif result["is_baseline"]:
                console.print(f"[green]Baseline recorded[/green] for {package} "
                               f"(observed via: {', '.join(snapshot.capabilities_used)})")
            elif result["changes"]:
                console.print(Panel(
                    "\n".join(f"[red]•[/red] {c}" for c in result["changes"]),
                    title=f"[bold red]Behavior change detected — {package}[/bold red]",
                    border_style="red",
                ))
                logger.warning(f"Behavior change for {package}: {result['changes']}")

                if not allowlist.is_trusted_package(package) and throttle.should_fire(package, "behavior_change"):
                    message = MessageBuilder.from_behavior_change(package, result["changes"])
                    _print_dispatch_result(dispatcher.dispatch(message))
            else:
                console.print(f"[dim]{datetime.now().strftime('%H:%M:%S')} — no change ({package})[/dim]")

            history.append(snapshot)
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped watching.[/yellow]")


def cmd_guard(args, config, logger) -> None:
    package = args.package
    interval = args.interval or config.get("guard_interval_seconds", 10)

    if args.notify:
        config = {**config, "alerts": {**config.get("alerts", {}), "termux_notify": True}}

    inspector = DeviceInspector(package)
    uid = inspector.get_uid()
    if not uid:
        console.print(f"[bold red]Error:[/bold red] Could not resolve UID for {package}.")
        sys.exit(1)
    if not os.path.isdir("/proc/net"):
        console.print("[bold red]Error:[/bold red] /proc/net not accessible on this system.")
        sys.exit(1)

    guard = RealtimeGuard(package, uid, store_dir=os.path.join(config.get("reports_dir", "reports"), "monitor"))
    dispatcher = AlertDispatcher(config, logger)
    allowlist = TrustAllowlist()
    throttle = AlertThrottle(config.get("alert_cooldown_seconds", 1800))

    console.print(f"[bold cyan]Real-time guard active for {package} (uid={uid}). "
                   f"Polling every {interval}s. Ctrl+C to stop.[/bold cyan]")
    console.print("[dim]Note: requires root/ADB for /proc/net visibility on most modern Android builds.[/dim]\n")

    poll_count = 0
    try:
        while True:
            alerts = guard.poll()
            poll_count += 1
            for alert in alerts:
                color = {"critical": "red", "warning": "yellow", "info": "cyan"}.get(alert.severity, "white")
                console.print(Panel(
                    alert.message,
                    title=f"[bold {color}]{alert.severity.upper()} — {alert.kind}[/bold {color}]",
                    border_style=color,
                ))
                logger.warning(f"[guard] {package}: {alert.message}")

                if not allowlist.is_trusted_package(package) and throttle.should_fire(package, alert.kind):
                    message = MessageBuilder.from_realtime_alert(
                        package=package, kind=alert.kind, severity=alert.severity, detail_message=alert.message,
                    )
                    _print_dispatch_result(dispatcher.dispatch(message))

            if not alerts and poll_count % 6 == 0:
                console.print(f"[dim]{datetime.now().strftime('%H:%M:%S')} — no suspicious activity ({package})[/dim]")

            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[yellow]Guard stopped.[/yellow]")


def cmd_notify_test(args, config, logger) -> None:
    dispatcher = AlertDispatcher(config, logger)
    message = MessageBuilder.test_message()
    sent = dispatcher.dispatch(message)
    if not sent:
        console.print("[yellow]No alert channels are enabled in config.json under 'alerts'.[/yellow]")
        return
    _print_dispatch_result(sent)


def cmd_trust(args, config, logger) -> None:
    allowlist = TrustAllowlist()
    if args.action == "add":
        allowlist.add_package(args.package)
        console.print(f"[green]Added {args.package} to trust allowlist.[/green]")
    elif args.action == "list":
        data = allowlist.list_trusted()
        table = Table(title="Trusted Packages")
        table.add_column("Package")
        for p in data.get("packages", []):
            table.add_row(p)
        console.print(table)


def cmd_status(args, config, logger) -> None:
    """Show a snapshot of all packages with monitoring history."""
    monitor_dir = os.path.join(config.get("reports_dir", "reports"), "monitor")
    if not os.path.isdir(monitor_dir):
        console.print("[yellow]No monitoring history found yet. Run 'watch' or 'guard' first.[/yellow]")
        return

    import json
    table = Table(title="APK Sentinel — Monitoring Status")
    table.add_column("Package")
    table.add_column("Last Check")
    table.add_column("Signals Observed")

    for fname in sorted(os.listdir(monitor_dir)):
        if not fname.endswith(".json") or fname.endswith("_realtime.jsonl") or "throttle" in fname:
            continue
        path = os.path.join(monitor_dir, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                history = json.load(f)
            if not history:
                continue
            last = history[-1]
            table.add_row(
                last.get("package", fname.replace(".json", "")),
                last.get("timestamp", "unknown"),
                ", ".join(last.get("capabilities_used", [])) or "none",
            )
        except (json.JSONDecodeError, OSError):
            continue

    console.print(table)


# ---------------------------------------------------------------------------
# CLI setup
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="apk-sentinel", description="APK Sentinel - Terminal-based APK malware scanner")
    parser.add_argument("--config", default="config.json", help="Path to config JSON file")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_p = subparsers.add_parser("scan", help="Scan a single APK file (static analysis)")
    scan_p.add_argument("apk_file", help="Path to the .apk file")
    scan_p.add_argument("--save-report", action="store_true", help="Also generate JSON/HTML/TXT/CSV reports")

    folder_p = subparsers.add_parser("scan-folder", help="Scan all APKs in a folder")
    folder_p.add_argument("folder", help="Path to the folder containing .apk files")
    folder_p.add_argument("--save-report", action="store_true", help="Also generate reports for each APK")

    report_p = subparsers.add_parser("report", help="Scan an APK and generate full reports")
    report_p.add_argument("apk_file", help="Path to the .apk file")

    diff_p = subparsers.add_parser("diff", help="Scan an APK and diff against its last saved report")
    diff_p.add_argument("apk_file", help="Path to the .apk file")

    watch_p = subparsers.add_parser("watch", help="Monitor an INSTALLED package for behavior drift over time")
    watch_p.add_argument("package", help="Installed package name, e.g. com.example.app")
    watch_p.add_argument("--interval", type=int, default=None, help="Seconds between checks (default from config)")

    guard_p = subparsers.add_parser("guard", help="Real-time intrusion/beaconing detection for an installed package")
    guard_p.add_argument("package", help="Installed package name, e.g. com.example.app")
    guard_p.add_argument("--interval", type=int, default=None, help="Seconds between polls (default from config)")
    guard_p.add_argument("--notify", action="store_true", help="Force-enable Termux phone notification for this run")

    notify_test_p = subparsers.add_parser("notify-test", help="Send a test alert through all enabled channels")

    trust_p = subparsers.add_parser("trust", help="Manage the trust allowlist for watch/guard")
    trust_p.add_argument("action", choices=["add", "list"])
    trust_p.add_argument("package", nargs="?", help="Package name (required for 'add')")

    status_p = subparsers.add_parser("status", help="Show monitoring status for all watched/guarded packages")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    config = load_config(args.config)
    logger = setup_logging(config.get("log_file", "apk_sentinel.log"), config.get("log_level", "INFO"))

    try:
        if args.command == "scan":
            cmd_scan(args, config, logger)
        elif args.command == "scan-folder":
            cmd_scan_folder(args, config, logger)
        elif args.command == "report":
            cmd_report(args, config, logger)
        elif args.command == "diff":
            cmd_diff(args, config, logger)
        elif args.command == "watch":
            cmd_watch(args, config, logger)
        elif args.command == "guard":
            cmd_guard(args, config, logger)
        elif args.command == "notify-test":
            cmd_notify_test(args, config, logger)
        elif args.command == "trust":
            cmd_trust(args, config, logger)
        elif args.command == "status":
            cmd_status(args, config, logger)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        sys.exit(130)
    except Exception as exc:
        logger.error(f"Unhandled exception: {exc}\n{traceback.format_exc()}")
        console.print(f"[bold red]Unexpected error:[/bold red] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
