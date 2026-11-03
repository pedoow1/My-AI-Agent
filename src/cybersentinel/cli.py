import argparse
import sys
import subprocess
import os
from rich.console import Console
from rich.table import Table
from .agents.master import CyberSentinelMaster
from .agents.report import ReportAgent
from .models import Severity

console = Console()

def main():
    parser = argparse.ArgumentParser(
        description="CyberSentinel: Advanced Cybersecurity Agent & Subagents Framework"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan a target directory or file for security vulnerabilities")
    scan_parser.add_argument("target", help="Path to file or directory to scan")
    scan_parser.add_argument("--output", "-o", help="Output report file path (supports .md or .json)")
    scan_parser.add_argument("--format", "-f", choices=["md", "json", "console"], default="console", help="Report format")
    scan_parser.add_argument("--ai", action="store_true", help="Enable Gemini AI remediation patch generation")

    # mission subcommand
    mission_parser = subparsers.add_parser("mission", help="Manage background tmux scanning missions")
    mission_subparsers = mission_parser.add_subparsers(dest="mission_action", help="Mission action")

    start_parser = mission_subparsers.add_parser("start", help="Start a background scanning mission in tmux")
    start_parser.add_argument("target", nargs="?", default=".", help="Path to file or directory to scan")

    mission_subparsers.add_parser("status", help="Check status of background tmux mission session")
    mission_subparsers.add_parser("logs", help="Tail persistent background mission logs")
    mission_subparsers.add_parser("attach", help="Attach to the running tmux mission session")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "mission":
        action = args.mission_action
        session_name = "cybersentinel-mission"
        log_file = "reports/mission_output.log"

        if action == "start":
            script_path = os.path.join(os.getcwd(), "scripts", "run_mission.sh")
            if os.path.exists(script_path):
                subprocess.run(["bash", script_path, args.target])
            else:
                console.print(f"[bold red]❌ Mission runner script not found at {script_path}[/bold red]")
                sys.exit(1)
        elif action == "status":
            res = subprocess.run(["tmux", "has-session", "-t", session_name], capture_output=True)
            if res.returncode == 0:
                console.print(f"[bold green]🟢 Background mission session '{session_name}' is currently RUNNING.[/bold green]")
                console.print(f"To attach: [cyan]cybersentinel mission attach[/cyan]")
                console.print(f"To view logs: [cyan]cybersentinel mission logs[/cyan]")
            else:
                console.print(f"[bold yellow]⚪ No active background mission session '{session_name}' found.[/bold yellow]")
        elif action == "logs":
            if os.path.exists(log_file):
                console.print(f"[bold cyan]📄 Tailing log file: {log_file}[/bold cyan]\n")
                try:
                    with open(log_file, "r", encoding="utf-8") as f:
                        print(f.read())
                except Exception as e:
                    console.print(f"[bold red]Error reading log file: {e}[/bold red]")
            else:
                console.print(f"[bold yellow]No log file found at {log_file}. Has a mission been started?[/bold yellow]")
        elif action == "attach":
            res = subprocess.run(["tmux", "has-session", "-t", session_name], capture_output=True)
            if res.returncode == 0:
                os.execvp("tmux", ["tmux", "attach", "-t", session_name])
            else:
                console.print(f"[bold red]❌ No active session '{session_name}' to attach to.[/bold red]")
                sys.exit(1)
        else:
            mission_parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        console.print(f"[bold cyan]🛡️ CyberSentinel[/bold cyan] initiating security assessment on target: [yellow]{args.target}[/yellow]\n")
        
        master = CyberSentinelMaster()
        with console.status("[bold green]Executing security subagents (CodeAuditAgent, InfraScanAgent, AiRemediationAgent)..."):
            result = master.scan(args.target, ai=args.ai)

        report_agent = ReportAgent()

        # Display Summary Table in Console
        table = Table(title="Security Scan Summary", show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        summary = result.summary()
        colors = {
            Severity.CRITICAL.value: "red",
            Severity.HIGH.value: "dark_orange",
            Severity.MEDIUM.value: "yellow",
            Severity.LOW.value: "blue",
            Severity.INFO.value: "cyan"
        }

        for sev, count in summary.items():
            color = colors.get(sev, "white")
            table.add_row(f"[{color}]{sev}[/{color}]", str(count))

        console.print(table)
        console.print(f"\n[bold]Total Findings:[/bold] {len(result.findings)}\n")

        if result.findings:
            console.print("[bold red]Top Findings Preview:[/bold red]")
            for f in result.findings[:5]:
                console.print(f"  • [{colors.get(f.severity.value, 'white')}]({f.severity.value})[/{colors.get(f.severity.value, 'white')}] {f.title} ({f.file_path or 'N/A'})")
            if len(result.findings) > 5:
                console.print(f"  ... and {len(result.findings) - 5} more findings.")

        # Handle file output if requested
        if args.output:
            output_path = args.output
            if output_path.endswith(".json") or args.format == "json":
                content = report_agent.generate_json_report(result)
                if not output_path.endswith(".json"):
                    output_path += ".json"
            else:
                content = report_agent.generate_markdown_report(result)
                if not output_path.endswith(".md"):
                    output_path += ".md"

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)
            console.print(f"\n[bold green]✅ Report successfully written to {output_path}[/bold green]")

        # Exit code based on critical/high findings
        critical_high_count = summary.get(Severity.CRITICAL.value, 0) + summary.get(Severity.HIGH.value, 0)
        if critical_high_count > 0:
            console.print(f"\n[bold red]⚠️ Security Assessment completed with {critical_high_count} Critical/High severity issues![/bold red]")
            sys.exit(2)
        else:
            console.print("\n[bold green]✨ Security Assessment completed successfully with no Critical/High severity issues.[/bold green]")
            sys.exit(0)

if __name__ == "__main__":
    main()
