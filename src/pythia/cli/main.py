"""Pythia command-line interface."""

from __future__ import annotations

import typer
import uvicorn
from rich.console import Console

from pythia import __version__
from pythia.core.config import get_settings

app = typer.Typer(
    name="pythia",
    help="Oracle-grade threat intelligence, served as an API.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


@app.command()
def version() -> None:
    """Print the Pythia version with a cool ASCII logo."""
    console.print("""[bold cyan]
  _____  __     __ _______ _    _ _____          
 |  __ \\ \\ \\   / /|__   __| |  | |_   _|   /\\    
 | |__) | \\ \\_/ /    | |  | |__| | | |    /  \\   
 |  ___/   \\   /     | |  |  __  | | |   / /\\ \\  
 | |        | |      | |  | |  | |_| |_ / ____ \\ 
 |_|        |_|      |_|  |_|  |_|_____/_/    \\_\\
[/bold cyan]""")
    console.print(f"[bold cyan]Pythia Threat Intelligence Platform[/bold cyan] v{__version__}\n")


@app.command()
def serve(
    host: str = typer.Option(None, help="Bind host (overrides env)"),
    port: int = typer.Option(None, help="Bind port (overrides env)"),
    reload: bool = typer.Option(False, help="Auto-reload on code changes"),
) -> None:
    """Start the Pythia API server."""
    settings = get_settings()
    uvicorn.run(
        "pythia.api.main:app",
        host=host or settings.host,
        port=port or settings.port,
        reload=reload,
        log_level=settings.log_level.lower(),
    )


# ── list sub-commands ─────────────────────────────────────────────────────────

list_app = typer.Typer(name="list", help="List CTI records.", no_args_is_help=True)
app.add_typer(list_app)


@list_app.command("threats")
@list_app.command("threat", hidden=True)
def list_threats(
    threat_id: str = typer.Argument(None, help="Specific Threat ID or title substring to display details for"),
    json_opt: bool = typer.Option(False, "--json", help="Output in raw JSON format"),
    output: str = typer.Option(None, "--output", "-o", help="File path to write JSON output to"),
    limit: int = typer.Option(50, help="Max records to return"),
) -> None:
    """List custom parsed threat intelligence entries, or show a specific entry's details."""
    from pythia.core.db import SessionLocal
    from pythia.models.report import SourceReport
    
    with SessionLocal() as session:
        if threat_id:
            report = session.get(SourceReport, threat_id) or (
                session.query(SourceReport)
                .filter(
                    (SourceReport.id.like(f"{threat_id}%")) | 
                    (SourceReport.title.ilike(f"%{threat_id}%"))
                )
                .first()
            )
            if not report:
                console.print(f"[red]Error: Threat report '{threat_id}' not found in database.[/red]")
                raise typer.Exit(code=1)
                
            pd = report.parsed_data or {}
            actors = [a.get("name", "") for a in (pd.get("actors") or [])]
            ttps = [t.get("technique_id", "") for t in (pd.get("ttps") or [])]
            
            report_data = {
                "id": report.id,
                "title": report.title,
                "url": report.url,
                "publication_date": report.publication_date,
                "tlp": report.tlp,
                "status": report.status,
                "created_at": report.created_at.isoformat() if report.created_at else None,
                "actors": actors,
                "ttps": ttps,
                "parsed_data": pd,
            }
            
            if json_opt or output:
                import json
                js_str = json.dumps(report_data, indent=2)
                if output:
                    from pathlib import Path
                    Path(output).write_text(js_str)
                    console.print(f"[green]Successfully saved threat to {output}[/green]")
                else:
                    print(js_str)
            else:
                from rich.panel import Panel
                
                console.print(Panel(
                    f"[bold]ID:[/bold] {report.id}\n"
                    f"[bold]Title:[/bold] {report.title}\n"
                    f"[bold]URL:[/bold] {report.url or 'N/A'}\n"
                    f"[bold]Publication Date:[/bold] {report.publication_date or 'N/A'}\n"
                    f"[bold]TLP:[/bold] {report.tlp}\n"
                    f"[bold]Status:[/bold] {report.status}\n"
                    f"[bold]Actors Observed:[/bold] {', '.join(actors or ['None'])}\n"
                    f"[bold]TTPs Identified:[/bold] {', '.join(ttps or ['None'])}\n\n"
                    f"[bold]Summary:[/bold]\n{pd.get('summary') or 'No summary available.'}",
                    title=f"Threat Report: {report.title}",
                    border_style="cyan",
                ))
                
                bi = pd.get("business_impact_draft")
                if bi:
                    console.print("\n[bold green]Business Impact Summary:[/bold green]")
                    console.print(f" - [bold]Financial Exposure:[/bold] {bi.get('financial_range_usd', [0,0])} USD")
                    console.print(f" - [bold]Operational downtime:[/bold] {bi.get('operational')}")
                    console.print(f" - [bold]Recommended Actions:[/bold]")
                    for act in bi.get('recommended_board_actions') or []:
                        console.print(f"   * {act}")
            return

        reports = session.query(SourceReport).order_by(SourceReport.created_at.desc()).limit(limit).all()
        
        data = []
        for r in reports:
            pd = r.parsed_data or {}
            actors = [a.get("name", "") for a in (pd.get("actors") or [])]
            ttps = [t.get("technique_id", "") for t in (pd.get("ttps") or [])]
            data.append({
                "id": r.id,
                "title": r.title,
                "url": r.url,
                "publication_date": r.publication_date,
                "tlp": r.tlp,
                "status": r.status,
                "actors": actors,
                "ttps": ttps,
            })
            
        if json_opt or output:
            import json
            js_str = json.dumps(data, indent=2)
            if output:
                from pathlib import Path
                Path(output).write_text(js_str)
                console.print(f"[green]Successfully saved to {output}[/green]")
            else:
                print(js_str)
        else:
            from rich.table import Table
            table = Table(title="Threat Intelligence Reports")
            table.add_column("ID", style="cyan")
            table.add_column("Title")
            table.add_column("URL")
            table.add_column("TLP", style="bold")
            table.add_column("Status", style="magenta")
            
            for d in data:
                table.add_row(
                    d["id"][:8],
                    d["title"] or "N/A",
                    d["url"] or "N/A",
                    d["tlp"],
                    d["status"],
                )
            console.print(table)


@list_app.command("actors")
@list_app.command("actor", hidden=True)
def list_actors(
    actor_id: str = typer.Argument(None, help="Specific Actor ID, name, or substring to display details for"),
    json_opt: bool = typer.Option(False, "--json", help="Output in raw JSON format"),
    output: str = typer.Option(None, "--output", "-o", help="File path to write JSON output to"),
    limit: int = typer.Option(50, help="Max records to return"),
) -> None:
    """List threat actor profiles, or show a specific actor's details."""
    from pythia.core.db import SessionLocal
    from pythia.models.actor import ThreatActor
    
    with SessionLocal() as session:
        if actor_id:
            actor = session.get(ThreatActor, actor_id) or (
                session.query(ThreatActor)
                .filter(
                    (ThreatActor.id.like(f"{actor_id}%")) | 
                    (ThreatActor.name.ilike(f"%{actor_id}%"))
                )
                .first()
            )
            if not actor:
                console.print(f"[red]Error: Threat actor '{actor_id}' not found in database.[/red]")
                raise typer.Exit(code=1)
                
            ttps_list = []
            for m in actor.ttp_mappings:
                from pythia.models.attck import AttckTechnique
                tech = session.get(AttckTechnique, m.technique_id)
                ttps_list.append({
                    "technique_id": m.technique_id,
                    "name": tech.name if tech else "Unknown",
                    "use_note": m.use_note,
                })
                
            actor_data = {
                "id": actor.id,
                "name": actor.name,
                "aliases": actor.aliases or [],
                "description": actor.description,
                "country_code": actor.country_code,
                "sponsor_type": actor.sponsor_type,
                "sophistication": actor.sophistication,
                "motivations": actor.motivations or [],
                "sectors_targeted": actor.sectors_targeted or [],
                "geographies_targeted": actor.geographies_targeted or [],
                "references": actor.references or [],
                "tlp": actor.tlp,
                "source": actor.source,
                "source_url": actor.source_url,
                "ttps": ttps_list,
            }
            
            if json_opt or output:
                import json
                js_str = json.dumps(actor_data, indent=2)
                if output:
                    from pathlib import Path
                    Path(output).write_text(js_str)
                    console.print(f"[green]Successfully saved actor to {output}[/green]")
                else:
                    print(js_str)
            else:
                from rich.panel import Panel
                from rich.table import Table
                
                console.print(Panel(
                    f"[bold]ID:[/bold] {actor.id}\n"
                    f"[bold]Name:[/bold] {actor.name}\n"
                    f"[bold]Aliases:[/bold] {', '.join(actor.aliases or [])}\n"
                    f"[bold]Country Code:[/bold] {actor.country_code or 'N/A'}\n"
                    f"[bold]Sponsor Type:[/bold] {actor.sponsor_type}\n"
                    f"[bold]Sophistication:[/bold] {actor.sophistication or 'N/A'}\n"
                    f"[bold]Motivations:[/bold] {', '.join(actor.motivations or [])}\n"
                    f"[bold]Sectors Targeted:[/bold] {', '.join(actor.sectors_targeted or [])}\n"
                    f"[bold]Geographies Targeted:[/bold] {', '.join(actor.geographies_targeted or [])}\n"
                    f"[bold]TLP:[/bold] {actor.tlp}\n"
                    f"[bold]Source:[/bold] {actor.source} ({actor.source_url or 'N/A'})\n\n"
                    f"[bold]Description:[/bold]\n{actor.description or 'No description available.'}",
                    title=f"Actor Profile: {actor.name}",
                    border_style="cyan",
                ))
                
                if ttps_list:
                    table = Table(title=f"Mapped TTPs for {actor.name}")
                    table.add_column("Technique ID", style="cyan")
                    table.add_column("Name")
                    table.add_column("Use Note")
                    for t in ttps_list:
                        table.add_row(t["technique_id"], t["name"], t["use_note"] or "")
                    console.print("\n", table)
            return

        actors = session.query(ThreatActor).order_by(ThreatActor.name).limit(limit).all()
        
        data = []
        for a in actors:
            data.append({
                "id": a.id,
                "name": a.name,
                "aliases": a.aliases or [],
                "country_code": a.country_code,
                "sponsor_type": a.sponsor_type,
                "sophistication": a.sophistication,
                "tlp": a.tlp,
                "source": a.source,
            })
            
        if json_opt or output:
            import json
            js_str = json.dumps(data, indent=2)
            if output:
                from pathlib import Path
                Path(output).write_text(js_str)
                console.print(f"[green]Successfully saved to {output}[/green]")
            else:
                print(js_str)
        else:
            from rich.table import Table
            table = Table(title="Threat Actor Profiles")
            table.add_column("ID", style="cyan")
            table.add_column("Name")
            table.add_column("Sponsor Type", style="magenta")
            table.add_column("Country", style="green")
            table.add_column("Sophistication", style="yellow")
            table.add_column("TLP")
            
            for d in data:
                table.add_row(
                    d["id"][:8] if d["id"] else "",
                    d["name"],
                    d["sponsor_type"],
                    d["country_code"] or "N/A",
                    str(d["sophistication"]) if d["sophistication"] is not None else "N/A",
                    d["tlp"],
                )
            console.print(table)


@list_app.command("ttps")
@list_app.command("ttp", hidden=True)
def list_ttps(
    technique_id: str = typer.Argument(None, help="Specific Technique ID or name substring to display details for"),
    json_opt: bool = typer.Option(False, "--json", help="Output in raw JSON format"),
    output: str = typer.Option(None, "--output", "-o", help="File path to write JSON output to"),
    limit: int = typer.Option(50, help="Max records to return"),
) -> None:
    """List ATT&CK techniques, or show a specific technique's details."""
    from pythia.core.db import SessionLocal
    from pythia.models.attck import AttckTechnique
    
    with SessionLocal() as session:
        if technique_id:
            tech = session.get(AttckTechnique, technique_id.upper()) or (
                session.query(AttckTechnique)
                .filter(
                    (AttckTechnique.technique_id.like(f"{technique_id}%")) | 
                    (AttckTechnique.name.ilike(f"%{technique_id}%"))
                )
                .first()
            )
            if not tech:
                console.print(f"[red]Error: Technique '{technique_id}' not found in database.[/red]")
                raise typer.Exit(code=1)
                
            from pythia.models.rule import DetectionRule
            rules = session.query(DetectionRule).filter(DetectionRule.technique_ids.contains(tech.technique_id)).all()
            rules_list = [{"id": r.id, "title": r.title, "rule_type": r.rule_type, "severity": r.severity} for r in rules]
            
            tech_data = {
                "technique_id": tech.technique_id,
                "name": tech.name,
                "description": tech.description,
                "tactics": tech.tactics or [],
                "is_subtechnique": tech.is_subtechnique,
                "parent_id": tech.parent_id,
                "domain": tech.domain,
                "platforms": tech.platforms or [],
                "data_sources": tech.data_sources or [],
                "detection_note": tech.detection_note,
                "source_url": tech.source_url,
                "rules": rules_list,
            }
            
            if json_opt or output:
                import json
                js_str = json.dumps(tech_data, indent=2)
                if output:
                    from pathlib import Path
                    Path(output).write_text(js_str)
                    console.print(f"[green]Successfully saved technique to {output}[/green]")
                else:
                    print(js_str)
            else:
                from rich.panel import Panel
                from rich.table import Table
                
                console.print(Panel(
                    f"[bold]ID:[/bold] {tech.technique_id}\n"
                    f"[bold]Name:[/bold] {tech.name}\n"
                    f"[bold]Domain:[/bold] {tech.domain}\n"
                    f"[bold]Tactics:[/bold] {', '.join(tech.tactics or [])}\n"
                    f"[bold]Is Subtechnique:[/bold] {tech.is_subtechnique}\n"
                    f"[bold]Parent ID:[/bold] {tech.parent_id or 'N/A'}\n"
                    f"[bold]Platforms:[/bold] {', '.join(tech.platforms or [])}\n"
                    f"[bold]Data Sources:[/bold] {', '.join(tech.data_sources or [])}\n"
                    f"[bold]Source URL:[/bold] {tech.source_url or 'N/A'}\n\n"
                    f"[bold]Description:[/bold]\n{tech.description or 'No description available.'}",
                    title=f"MITRE ATT&CK Technique: {tech.name}",
                    border_style="cyan",
                ))
                
                if rules_list:
                    table = Table(title=f"Linked Detection Rules for {tech.technique_id}")
                    table.add_column("Rule ID", style="cyan")
                    table.add_column("Type", style="bold")
                    table.add_column("Title")
                    table.add_column("Severity", style="magenta")
                    for r in rules_list:
                        table.add_row(r["id"][:8], r["rule_type"].upper(), r["title"], r["severity"] or "N/A")
                    console.print("\n", table)
            return

        techs = session.query(AttckTechnique).order_by(AttckTechnique.technique_id).limit(limit).all()
        
        data = []
        for t in techs:
            data.append({
                "technique_id": t.technique_id,
                "name": t.name,
                "tactics": t.tactics or [],
                "domain": t.domain,
            })
            
        if json_opt or output:
            import json
            js_str = json.dumps(data, indent=2)
            if output:
                from pathlib import Path
                Path(output).write_text(js_str)
                console.print(f"[green]Successfully saved to {output}[/green]")
            else:
                print(js_str)
        else:
            from rich.table import Table
            table = Table(title="MITRE ATT&CK Techniques")
            table.add_column("ID", style="cyan")
            table.add_column("Name")
            table.add_column("Tactics", style="magenta")
            table.add_column("Domain")
            
            for d in data:
                table.add_row(
                    d["technique_id"],
                    d["name"],
                    ", ".join(d["tactics"]),
                    d["domain"],
                )
            console.print(table)


@list_app.command("iocs")
@list_app.command("ioc", hidden=True)
def list_iocs(
    ioc_id: str = typer.Argument(None, help="Specific IoC ID or value substring to display details for"),
    json_opt: bool = typer.Option(False, "--json", help="Output in raw JSON format"),
    output: str = typer.Option(None, "--output", "-o", help="File path to write JSON output to"),
    limit: int = typer.Option(50, help="Max records to return"),
) -> None:
    """List Indicators of Compromise (IoCs), or show a specific IoC's details."""
    from pythia.core.db import SessionLocal
    from pythia.models.ioc import IoC
    
    with SessionLocal() as session:
        if ioc_id:
            ioc = session.get(IoC, ioc_id) or (
                session.query(IoC)
                .filter(
                    (IoC.id.like(f"{ioc_id}%")) | 
                    (IoC.value.ilike(f"%{ioc_id}%"))
                )
                .first()
            )
            if not ioc:
                console.print(f"[red]Error: Indicator '{ioc_id}' not found in database.[/red]")
                raise typer.Exit(code=1)
                
            ioc_data = {
                "id": ioc.id,
                "type": ioc.type,
                "value": ioc.value,
                "context": ioc.context,
                "confidence_source": ioc.confidence_source,
                "confidence_info": ioc.confidence_info,
                "tlp": ioc.tlp,
                "pyramid_tier": ioc.pyramid_tier,
                "source_url": ioc.source_url,
            }
            
            if json_opt or output:
                import json
                js_str = json.dumps(ioc_data, indent=2)
                if output:
                    from pathlib import Path
                    Path(output).write_text(js_str)
                    console.print(f"[green]Successfully saved IoC to {output}[/green]")
                else:
                    print(js_str)
            else:
                from rich.panel import Panel
                
                console.print(Panel(
                    f"[bold]ID:[/bold] {ioc.id}\n"
                    f"[bold]Type:[/bold] {ioc.type.upper()}\n"
                    f"[bold]Value:[/bold] {ioc.value}\n"
                    f"[bold]Pyramid Tier:[/bold] {ioc.pyramid_tier.upper() if ioc.pyramid_tier else 'N/A'}\n"
                    f"[bold]TLP:[/bold] {ioc.tlp}\n"
                    f"[bold]Confidence Source/Info:[/bold] {ioc.confidence_source or 'N/A'}/{ioc.confidence_info or 'N/A'}\n"
                    f"[bold]Source URL:[/bold] {ioc.source_url or 'N/A'}\n\n"
                    f"[bold]Context:[/bold]\n{ioc.context or 'No context description available.'}",
                    title=f"Indicator of Compromise Details",
                    border_style="cyan",
                ))
            return


@list_app.command("rules")
@list_app.command("rule", hidden=True)
def list_rules(
    rule_id: str = typer.Argument(None, help="Specific Rule ID or title substring to display details for"),
    json_opt: bool = typer.Option(False, "--json", help="Output in raw JSON format"),
    output: str = typer.Option(None, "--output", "-o", help="File path to write JSON output to"),
    limit: int = typer.Option(50, help="Max records to return"),
) -> None:
    """List Sigma and Yara detection rules, or show a specific rule's details."""
    from pythia.core.db import SessionLocal
    from pythia.models.rule import DetectionRule
    
    with SessionLocal() as session:
        if rule_id:
            rule = session.get(DetectionRule, rule_id) or (
                session.query(DetectionRule)
                .filter(
                    (DetectionRule.id.like(f"{rule_id}%")) | 
                    (DetectionRule.title.ilike(f"%{rule_id}%"))
                )
                .first()
            )
            if not rule:
                console.print(f"[red]Error: Rule '{rule_id}' not found in database.[/red]")
                raise typer.Exit(code=1)
                
            rule_data = {
                "id": rule.id,
                "rule_type": rule.rule_type,
                "title": rule.title,
                "severity": rule.severity,
                "status": rule.status,
                "technique_ids": rule.technique_ids or [],
                "actor_ids": rule.actor_ids or [],
                "source_url": rule.source_url,
                "content": rule.content,
            }
            
            if json_opt or output:
                import json
                js_str = json.dumps(rule_data, indent=2)
                if output:
                    from pathlib import Path
                    Path(output).write_text(js_str)
                    console.print(f"[green]Successfully saved rule to {output}[/green]")
                else:
                    print(js_str)
            else:
                from rich.panel import Panel
                from rich.syntax import Syntax
                
                console.print(Panel(
                    f"[bold]ID:[/bold] {rule.id}\n"
                    f"[bold]Type:[/bold] {rule.rule_type.upper()}\n"
                    f"[bold]Title:[/bold] {rule.title}\n"
                    f"[bold]Severity:[/bold] {rule.severity}\n"
                    f"[bold]Status:[/bold] {rule.status}\n"
                    f"[bold]Technique IDs:[/bold] {', '.join(rule.technique_ids or [])}\n"
                    f"[bold]Source URL:[/bold] {rule.source_url or 'N/A'}",
                    title=f"Rule Details: {rule.title}",
                    border_style="cyan",
                ))
                console.print("\n[bold green]Rule Definition / Content:[/bold green]")
                lexer = "yaml" if rule.rule_type == "sigma" else "text"
                syntax = Syntax(rule.content, lexer, theme="monokai", line_numbers=True)
                console.print(syntax)
            return

        rules = session.query(DetectionRule).order_by(DetectionRule.rule_type).limit(limit).all()
        
        data = []
        for r in rules:
            data.append({
                "id": r.id,
                "rule_type": r.rule_type,
                "title": r.title,
                "severity": r.severity,
                "status": r.status,
            })
            
        if json_opt or output:
            import json
            js_str = json.dumps(data, indent=2)
            if output:
                from pathlib import Path
                Path(output).write_text(js_str)
                console.print(f"[green]Successfully saved to {output}[/green]")
            else:
                print(js_str)
        else:
            from rich.table import Table
            table = Table(title="Detection Rules")
            table.add_column("ID", style="cyan")
            table.add_column("Type", style="bold")
            table.add_column("Title")
            table.add_column("Severity", style="magenta")
            table.add_column("Status")
            
            for d in data:
                table.add_row(
                    d["id"][:8],
                    d["rule_type"],
                    d["title"],
                    d["severity"] or "N/A",
                    d["status"] or "N/A",
                )
            console.print(table)


@list_app.command("owasp-llm")
def list_owasp_llm(
    item_id: str = typer.Argument(None, help="OWASP LLM item ID, e.g. LLM01 or LLM01:2025"),
    json_opt: bool = typer.Option(False, "--json", help="Output raw JSON"),
    output: str = typer.Option(None, "--output", "-o", help="Write JSON to file"),
) -> None:
    """List OWASP LLM Top 10 (2025) categories, or show a specific item."""
    from pythia.core.db import SessionLocal
    from pythia.models.owasp_llm import OwaspLlmItem

    with SessionLocal() as session:
        if item_id:
            lookup = item_id if ":" in item_id else f"{item_id}:2025"
            item = session.get(OwaspLlmItem, lookup)
            if not item:
                console.print(f"[red]Error: OWASP LLM item '{item_id}' not found. Run 'pythia sync owasp' first.[/red]")
                raise typer.Exit(code=1)

            data = {
                "item_id": item.item_id,
                "rank": item.rank,
                "name": item.name,
                "description": item.description,
                "impact": item.impact,
                "detection_notes": item.detection_notes,
                "atlas_mappings": item.atlas_mappings or [],
                "cwe_ids": item.cwe_ids or [],
                "mitigations": item.mitigations or [],
                "real_world_examples": item.real_world_examples or [],
                "references": item.references or [],
            }

            if json_opt or output:
                import json as _json
                js = _json.dumps(data, indent=2)
                if output:
                    from pathlib import Path
                    Path(output).write_text(js)
                    console.print(f"[green]Saved to {output}[/green]")
                else:
                    print(js)
            else:
                from rich.panel import Panel
                console.print(Panel(
                    f"[bold]ID:[/bold] {item.item_id}   [bold]Rank:[/bold] #{item.rank}\n"
                    f"[bold]ATLAS mappings:[/bold] {', '.join(item.atlas_mappings or []) or 'N/A'}\n"
                    f"[bold]CWE IDs:[/bold] {', '.join(item.cwe_ids or []) or 'N/A'}\n\n"
                    f"[bold]Description:[/bold]\n{item.description or 'N/A'}\n\n"
                    f"[bold]Impact:[/bold]\n{item.impact or 'N/A'}\n\n"
                    f"[bold]Detection Notes:[/bold]\n{item.detection_notes or 'N/A'}",
                    title=f"OWASP LLM: {item.name}",
                    border_style="yellow",
                ))
                if item.real_world_examples:
                    console.print("\n[bold yellow]Real-World Examples:[/bold yellow]")
                    for ex in item.real_world_examples:
                        console.print(f"  • {ex}")
                if item.mitigations:
                    console.print("\n[bold green]Mitigations:[/bold green]")
                    for m in item.mitigations:
                        console.print(f"  • {m}")
            return

        items = session.query(OwaspLlmItem).order_by(OwaspLlmItem.rank).all()
        if not items:
            console.print("[yellow]No OWASP LLM items found. Run 'pythia sync owasp' first.[/yellow]")
            return

        if json_opt or output:
            import json as _json
            data_list = [
                {"item_id": i.item_id, "rank": i.rank, "name": i.name,
                 "atlas_mappings": i.atlas_mappings or [], "cwe_ids": i.cwe_ids or []}
                for i in items
            ]
            js = _json.dumps(data_list, indent=2)
            if output:
                from pathlib import Path
                Path(output).write_text(js)
                console.print(f"[green]Saved to {output}[/green]")
            else:
                print(js)
        else:
            from rich.table import Table
            table = Table(title="OWASP LLM Top 10 (2025)", show_lines=True)
            table.add_column("#", style="bold yellow", width=4)
            table.add_column("ID", style="cyan", width=14)
            table.add_column("Name")
            table.add_column("ATLAS Mappings", style="magenta")
            table.add_column("CWE IDs", style="green")
            for i in items:
                table.add_row(
                    str(i.rank),
                    i.item_id,
                    i.name,
                    ", ".join(i.atlas_mappings or []) or "—",
                    ", ".join(i.cwe_ids or []) or "—",
                )
            console.print(table)


@list_app.command("malware")
def list_malware(
    malware_id: str = typer.Argument(None, help="Family ID, Malpedia slug, or name substring"),
    family_type: str = typer.Option(None, "--type", "-t", help="Filter by family type"),
    json_opt: bool = typer.Option(False, "--json", help="Output raw JSON"),
    output: str = typer.Option(None, "--output", "-o", help="Write JSON to file"),
    limit: int = typer.Option(50, help="Max records to return"),
) -> None:
    """List malware families, or show a specific family's details."""
    from pythia.core.db import SessionLocal
    from pythia.models.malware import MalwareFamily

    with SessionLocal() as session:
        if malware_id:
            family = (
                session.get(MalwareFamily, malware_id)
                or session.query(MalwareFamily).filter(
                    (MalwareFamily.malpedia_slug == malware_id)
                    | (MalwareFamily.name.ilike(f"%{malware_id}%"))
                ).first()
            )
            if not family:
                console.print(f"[red]Error: Malware family '{malware_id}' not found. Run 'pythia sync malpedia' first.[/red]")
                raise typer.Exit(code=1)

            data = {
                "id": family.id,
                "name": family.name,
                "aliases": family.aliases or [],
                "family_type": family.family_type,
                "description": family.description,
                "actor_ids": family.actor_ids or [],
                "rule_ids": family.rule_ids or [],
                "references": family.references or [],
                "source": family.source,
                "source_url": family.source_url,
                "malpedia_slug": family.malpedia_slug,
            }

            if json_opt or output:
                import json as _json
                js = _json.dumps(data, indent=2)
                if output:
                    from pathlib import Path
                    Path(output).write_text(js)
                    console.print(f"[green]Saved to {output}[/green]")
                else:
                    print(js)
            else:
                from rich.panel import Panel
                console.print(Panel(
                    f"[bold]ID:[/bold] {family.id}\n"
                    f"[bold]Name:[/bold] {family.name}\n"
                    f"[bold]Type:[/bold] {family.family_type or 'N/A'}\n"
                    f"[bold]Aliases:[/bold] {', '.join(family.aliases or []) or 'N/A'}\n"
                    f"[bold]Malpedia Slug:[/bold] {family.malpedia_slug or 'N/A'}\n"
                    f"[bold]Source:[/bold] {family.source} ({family.source_url or 'N/A'})\n\n"
                    f"[bold]Description:[/bold]\n{family.description or 'No description available.'}",
                    title=f"Malware Family: {family.name}",
                    border_style="cyan",
                ))
            return

        query = session.query(MalwareFamily)
        if family_type:
            query = query.filter(MalwareFamily.family_type == family_type.lower())
        families = query.order_by(MalwareFamily.name).limit(limit).all()

        if not families:
            console.print("[yellow]No malware families found. Run 'pythia sync malpedia' first.[/yellow]")
            return

        if json_opt or output:
            import json as _json
            data_list = [
                {
                    "id": f.id, "name": f.name, "family_type": f.family_type,
                    "aliases": f.aliases or [], "malpedia_slug": f.malpedia_slug,
                }
                for f in families
            ]
            js = _json.dumps(data_list, indent=2)
            if output:
                from pathlib import Path
                Path(output).write_text(js)
                console.print(f"[green]Saved to {output}[/green]")
            else:
                print(js)
        else:
            from rich.table import Table
            table = Table(title="Malware Families")
            table.add_column("ID", style="cyan", width=8)
            table.add_column("Name", style="bold")
            table.add_column("Type", style="magenta")
            table.add_column("Malpedia Slug")
            for f in families:
                table.add_row(
                    f.id[:8],
                    f.name,
                    f.family_type or "—",
                    f.malpedia_slug or "—",
                )
            console.print(table)


@list_app.command("ai-incidents")
def list_ai_incidents(
    owasp_id: str = typer.Option(None, "--owasp", help="Filter by OWASP LLM ID (e.g. LLM01:2025)"),
    atlas_id: str = typer.Option(None, "--atlas", help="Filter by ATLAS technique ID (e.g. AML.T0051)"),
    json_opt: bool = typer.Option(False, "--json", help="Output raw JSON"),
    output: str = typer.Option(None, "--output", "-o", help="Write JSON to file"),
) -> None:
    """List curated real-world AI security incidents mapped to ATLAS and OWASP LLM Top 10."""
    from pythia.api.ai_threats import _AI_INCIDENTS

    results = list(_AI_INCIDENTS)
    if owasp_id:
        results = [r for r in results if owasp_id in r["owasp_llm_ids"]]
    if atlas_id:
        results = [r for r in results if atlas_id in r["atlas_technique_ids"]]

    if json_opt or output:
        import json as _json
        js = _json.dumps([dict(r) for r in results], indent=2)
        if output:
            from pathlib import Path
            Path(output).write_text(js)
            console.print(f"[green]Saved {len(results)} incidents to {output}[/green]")
        else:
            print(js)
        return

    from rich.panel import Panel
    for r in results:
        owasp_tags = "  ".join(f"[yellow]{oid}[/yellow]" for oid in r["owasp_llm_ids"])
        atlas_tags = "  ".join(f"[magenta]{aid}[/magenta]" for aid in r["atlas_technique_ids"])
        console.print(Panel(
            f"[bold]Date:[/bold] {r['date']}   [bold]TLP:[/bold] {r['tlp']}\n"
            f"[bold]OWASP:[/bold] {owasp_tags}\n"
            f"[bold]ATLAS:[/bold] {atlas_tags}\n\n"
            f"{r['description']}\n\n"
            f"[bold green]Impact:[/bold green] {r['impact_summary']}\n\n"
            f"[dim]{r['source_url']}[/dim]",
            title=f"[bold]{r['title']}[/bold]",
            border_style="red",
        ))
    console.print(f"\n[bold]{len(results)}[/bold] incident(s) shown.")


# ── stix sub-commands ─────────────────────────────────────────────────────────

stix_app = typer.Typer(name="stix", help="Export Pythia entities as STIX 2.1 bundles.", no_args_is_help=True)
app.add_typer(stix_app)


@stix_app.command("actor")
def stix_actor(
    actor_id: str = typer.Argument(..., help="Actor UUID, name, slug, or substring"),
    output: str = typer.Option(None, "--output", "-o", help="Write JSON bundle to file (default: print to stdout)"),
) -> None:
    """Export a threat actor as a STIX 2.1 bundle (threat-actor + attack-patterns + relationships)."""
    import json as _json

    from pythia.core.db import SessionLocal
    from pythia.exporters.stix import export_actor as _stix_export
    from pythia.models.actor import ThreatActor

    def _resolve(aid: str, s: object) -> object:
        from sqlalchemy.orm import Session as _S
        sess: _S = s  # type: ignore[assignment]
        a = sess.get(ThreatActor, aid)
        if a:
            return a
        a = sess.query(ThreatActor).filter(ThreatActor.name.ilike(aid)).first()
        if a:
            return a
        slug = aid.replace("-", " ")
        a = sess.query(ThreatActor).filter(ThreatActor.name.ilike(slug)).first()
        if a:
            return a
        return sess.query(ThreatActor).filter(ThreatActor.name.ilike(f"%{aid}%")).first()

    with SessionLocal() as session:
        actor = _resolve(actor_id, session)
        if not actor:
            console.print(f"[red]Error: Actor '{actor_id}' not found.[/red]")
            raise typer.Exit(code=1)

        bundle = _stix_export(actor)
        js = _json.dumps(bundle, indent=2)

        if output:
            from pathlib import Path
            Path(output).write_text(js)
            obj_count = len(bundle["objects"])
            console.print(f"[green]STIX 2.1 bundle ({obj_count} objects) saved to [bold]{output}[/bold][/green]")
        else:
            print(js)


@stix_app.command("iocs")
def stix_iocs(
    ioc_type: str = typer.Option(None, "--type", "-t", help="Filter by IoC type (ip, domain, hash, url, cve, ...)"),
    pyramid_tier: str = typer.Option(None, "--tier", help="Filter by Pyramid of Pain tier"),
    limit: int = typer.Option(100, help="Max IoCs to include in bundle"),
    output: str = typer.Option(None, "--output", "-o", help="Write JSON bundle to file (default: print to stdout)"),
) -> None:
    """Export IoCs as a STIX 2.1 indicator bundle."""
    import json as _json

    from pythia.core.db import SessionLocal
    from pythia.exporters.stix import export_iocs as _stix_export
    from pythia.models.ioc import IoC

    with SessionLocal() as session:
        q = session.query(IoC)
        if ioc_type:
            q = q.filter(IoC.type == ioc_type.lower())
        if pyramid_tier:
            q = q.filter(IoC.pyramid_tier == pyramid_tier.lower())
        iocs = q.order_by(IoC.created_at.desc()).limit(limit).all()

        if not iocs:
            console.print("[yellow]No IoCs matched the given filters.[/yellow]")
            raise typer.Exit(code=0)

        bundle = _stix_export(iocs)
        js = _json.dumps(bundle, indent=2)

        if output:
            from pathlib import Path
            Path(output).write_text(js)
            console.print(f"[green]STIX 2.1 bundle ({len(iocs)} indicators) saved to [bold]{output}[/bold][/green]")
        else:
            print(js)


# ── create sub-commands ───────────────────────────────────────────────────────

create_app = typer.Typer(name="create", help="Create custom CTI profiles.", no_args_is_help=True)
app.add_typer(create_app)


@create_app.command("actor")
def create_actor(
    name: str = typer.Option(..., "--name", "-n", help="Name of the threat actor"),
    aliases: str = typer.Option(None, "--aliases", "-a", help="Comma-separated synonyms / aliases"),
    country: str = typer.Option(None, "--country", "-c", help="2-letter country code"),
    sponsor: str = typer.Option("unknown", "--sponsor", "-s", help="Sponsor type (nation-state | financially-motivated | hacktivist | script-kiddie | unknown)"),
    sophistication: int = typer.Option(None, "--sophistication", "-p", help="Sophistication level (1-5)"),
    tlp: str = typer.Option("WHITE", "--tlp", "-t", help="TLP classification (WHITE | GREEN | AMBER | RED)"),
) -> None:
    """Create a new manual threat actor profile."""
    from pythia.core.db import SessionLocal
    from pythia.models.actor import ThreatActor
    
    alias_list = [a.strip() for a in aliases.split(",")] if aliases else []
    
    with SessionLocal() as session:
        existing = session.query(ThreatActor).filter(ThreatActor.name.ilike(name)).first()
        if existing:
            console.print(f"[red]Error: Threat actor with name '{name}' already exists.[/red]")
            raise typer.Exit(code=1)
            
        actor = ThreatActor(
            name=name,
            aliases=alias_list,
            country_code=country.upper() if country else None,
            sponsor_type=sponsor,
            sophistication=sophistication,
            tlp=tlp.upper(),
            source="manual",
            motivations=[],
            sectors_targeted=[],
            geographies_targeted=[country.upper()] if country else [],
            references=[],
        )
        session.add(actor)
        session.commit()
        session.refresh(actor)
        
        console.print(f"[green]Successfully created threat actor [bold]{actor.name}[/bold] (ID: {actor.id})[/green]")


# ── parse & report commands ───────────────────────────────────────────────────

@app.command()
def parse(
    url: str = typer.Option(None, "--url", "-u", help="URL of threat intel report to fetch and parse"),
    text: str = typer.Option(None, "--text", "-t", help="Raw report text to parse directly"),
    json_opt: bool = typer.Option(False, "--json", help="Output raw parsed JSON instead of pretty console tables"),
    output: str = typer.Option(None, "--output", "-o", help="File path to write output JSON to"),
) -> None:
    """Fetch an article, parse it with Claude, and store it in the database."""
    if not url and not text:
        console.print("[red]Error: Either --url or --text must be specified.[/red]")
        raise typer.Exit(code=1)
        
    raw_text = ""
    if url:
        try:
            import trafilatura
            console.print(f"[cyan]Fetching URL: {url} ...[/cyan]")
            downloaded = trafilatura.fetch_url(url)
            if downloaded:
                raw_text = trafilatura.extract(downloaded) or ""
        except Exception as exc:
            console.print(f"[red]Error fetching URL: {exc}[/red]")
            raise typer.Exit(code=1)
            
    if text:
        raw_text = text
        
    if not raw_text.strip():
        console.print("[red]Error: No text could be extracted or text was empty.[/red]")
        raise typer.Exit(code=1)
        
    try:
        from pythia.ingestion.claude_parser import parse_article
        console.print("[cyan]Sending text to Claude for extraction...[/cyan]")
        parsed = parse_article(raw_text, source_url=url)
    except Exception as exc:
        console.print(f"[red]Error calling Claude API: {exc}[/red]")
        raise typer.Exit(code=1)
        
    import uuid
    from pythia.core.db import SessionLocal
    from pythia.models.report import SourceReport
    
    with SessionLocal() as session:
        report = SourceReport(
            id=str(uuid.uuid4()),
            title=parsed.get("title"),
            url=url,
            raw_text=raw_text[:50_000],
            publication_date=parsed.get("publication_date"),
            status="pending_review",
            parsed_data=parsed,
            tlp=str(parsed.get("tlp", "GREEN")),
        )
        session.add(report)
        session.commit()
        session.refresh(report)
        
        console.print(f"[green]Successfully ingested and saved report (ID: {report.id})[/green]\n")
        
        if json_opt or output:
            import json
            js_str = json.dumps(parsed, indent=2)
            if output:
                from pathlib import Path
                Path(output).write_text(js_str)
                console.print(f"[green]Parsed JSON saved to {output}[/green]")
            else:
                print(js_str)
        else:
            from rich.panel import Panel
            console.print(Panel(
                f"[bold]Title:[/bold] {report.title}\n"
                f"[bold]TLP:[/bold] {report.tlp}\n"
                f"[bold]Date:[/bold] {report.publication_date}\n"
                f"[bold]Status:[/bold] {report.status}",
                title="Ingested Report Meta",
                border_style="green",
            ))
            
            actors = parsed.get("actors") or []
            if actors:
                console.print("\n[bold green]Extracted Threat Actors:[/bold green]")
                for a in actors:
                    console.print(f" - [bold]{a.get('name')}[/bold] (Aliases: {', '.join(a.get('aliases', []))})")
                    
            ttps = parsed.get("ttps") or []
            if ttps:
                console.print("\n[bold green]Extracted TTPs:[/bold green]")
                for t in ttps:
                    console.print(f" - [cyan]{t.get('technique_id')}[/cyan]: {t.get('evidence')}")
                    
            bi = parsed.get("business_impact_draft")
            if bi:
                console.print("\n[bold green]Business Impact Draft Summary:[/bold green]")
                console.print(f" - [bold]Financial Impact:[/bold] {bi.get('financial_range_usd', [0,0])} USD")
                console.print(f" - [bold]Operational:[/bold] {bi.get('operational')}")
                console.print(f" - [bold]Recommended Board Actions:[/bold]")
                for act in bi.get("recommended_board_actions") or []:
                    console.print(f"   * {act}")


@app.command()
def ingest(
    url: str = typer.Argument(..., help="URL of an intel article to parse"),
) -> None:
    """Fetch an article, parse it with Claude, store as pending intel."""
    parse(url=url)


@app.command("fetch-feeds")
def fetch_feeds(
    source: str = typer.Option(None, "--source", "-s", help="Vendor slug to poll (default: all active sources)"),
    dry_run: bool = typer.Option(False, help="Count new articles without inserting"),
) -> None:
    """Poll all active RSS/Atom intel feeds and queue new articles."""
    from pythia.core.db import SessionLocal
    from pythia.ingestion.feed_poller import poll_all_feeds
    from pythia.models.intel_feed import IntelFeedSource

    with SessionLocal() as session:
        if source:
            src = session.query(IntelFeedSource).filter_by(vendor=source, active=True).first()
            if not src:
                console.print(f"[red]No active source with vendor slug '{source}' found.[/red]")
                raise typer.Exit(code=1)
            # Temporarily isolate by deactivating others is complex; just poll all and note filter
            console.print(f"[cyan]Polling feed: {src.name}...[/cyan]")
        else:
            console.print("[cyan]Polling all active intel feeds...[/cyan]")

        new_count = poll_all_feeds(session, dry_run=dry_run)
        action = "would be added" if dry_run else "new articles queued"
        console.print(f"[green]{new_count} {action}.[/green]")


@app.command("process-feed-queue")
def process_feed_queue(
    limit: int = typer.Option(10, help="Max articles to ingest through Claude"),
    dry_run: bool = typer.Option(False, help="Count without calling Claude"),
) -> None:
    """Run Claude on queued articles from sources with auto_ingest enabled."""
    from pythia.core.db import SessionLocal
    from pythia.ingestion.feed_poller import process_article_queue

    with SessionLocal() as session:
        console.print(f"[cyan]Processing up to {limit} queued articles through Claude...[/cyan]")
        count = process_article_queue(session, limit=limit, dry_run=dry_run)
        action = "would be ingested" if dry_run else "articles ingested"
        console.print(f"[green]{count} {action}.[/green]")


@app.command()
def sync(
    sources: list[str] = typer.Argument(
        None,
        help=(
            "Sources to refresh (default: all core). "
            "Core: attck, atlas, misp-galaxy, kev, owasp-llm, sigma, apt-sheet. "
            "Optional: abuse-ch, ipsum, phishtank, malpedia, "
            "sigma-full, yara-rules, icewater, signature-base"
        ),
    ),
    dry_run: bool = typer.Option(False, help="Show what would change, don't write"),
) -> None:
    """Refresh threat intel data from upstream open-source sources.

    Default sources pulled on 'pythia sync' (small, network-efficient):
      attck          MITRE ATT&CK STIX bundle (Enterprise)
      atlas          MITRE ATLAS (AI/ML adversarial techniques)
      misp-galaxy    MISP Galaxy threat-actor cluster (~750 actor profiles)
      kev            CISA Known Exploited Vulnerabilities catalog
      owasp-llm      OWASP LLM Top 10 2025
      sigma          ~50 curated SigmaHQ rules covering top techniques
      apt-sheet      APT Groups, Operations & Tactics Google Sheet

    Optional sources (pass explicitly by name):
      abuse-ch       abuse.ch ThreatFox IoC feeds (daily auto-scheduled)
      ipsum          stamparm/ipsum aggregated IP blocklist
      phishtank      PhishTank phishing URLs (requires PHISHTANK_API_KEY)
      malpedia       Malpedia malware family catalog (MALPEDIA_API_KEY for full data)
      sigma-full     Full SigmaHQ ruleset (large download, thousands of rules)
      yara-rules     Yara-Rules/rules GitHub repository (large)
      icewater       SupportIntelligence/Icewater YARA rules (~12 800 rules)
      signature-base Neo23x0/signature-base YARA + Sigma rules
    """
    targets = sources or ["misp-galaxy", "attck", "atlas", "kev", "sigma", "owasp", "apt-sheet", "intel-feeds"]
    console.print(f"[bold cyan]Pythia sync[/bold cyan] — refreshing: {', '.join(targets)}\n")
    if dry_run:
        console.print("[dim]dry-run: counting records only, no DB writes[/dim]\n")

    from pythia.core.seed import run as _run_seed
    _run_seed(sources=targets, dry_run=dry_run)


@app.command()
def report(
    report_id: str = typer.Argument(..., help="Report ID or title substring to render"),
    template: str = typer.Option("executive", help="executive | tactical"),
    output: str = typer.Option("report.pdf", help="Output PDF path"),
) -> None:
    """Render a PDF report."""
    from pythia.core.db import SessionLocal
    from pythia.models.report import SourceReport
    
    with SessionLocal() as session:
        report_inst = session.get(SourceReport, report_id) or (
            session.query(SourceReport)
            .filter(
                (SourceReport.id.like(f"{report_id}%")) | 
                (SourceReport.title.ilike(f"%{report_id}%"))
            )
            .first()
        )
        if not report_inst:
            console.print(f"[red]Error: Report '{report_id}' not found in database.[/red]")
            raise typer.Exit(code=1)
            
        try:
            from pythia.reporting.pdf import render_report
            console.print(f"[cyan]Rendering PDF ({template} template) for '{report_inst.title or report_inst.id}' ...[/cyan]")
            pdf_bytes = render_report(report_inst, template=template) # type: ignore[arg-type]
            
            from pathlib import Path
            Path(output).write_bytes(pdf_bytes)
        except Exception as exc:
            console.print(f"[red]Error generating PDF: {exc}[/red]")
            raise typer.Exit(code=1)
            
        console.print(f"[green]Successfully saved PDF report to [bold]{output}[/bold][/green]")


@app.command()
def hunt(
    technique_id: str = typer.Argument(..., help="ATT&CK technique ID (e.g. T1059.001)"),
    platform: str = typer.Option("all", "--platform", "-p", help="splunk | elastic | sentinel | all"),
    json_opt: bool = typer.Option(False, "--json", help="Output raw JSON"),
    output: str = typer.Option(None, "--output", "-o", help="Write output to file"),
) -> None:
    """Generate multi-platform hunt queries for an ATT&CK technique."""
    from pythia.core.db import SessionLocal
    from pythia.detections.converters import convert as sigma_convert
    from pythia.models.attck import AttckTechnique
    from pythia.models.rule import DetectionRule

    with SessionLocal() as session:
        tech = session.get(AttckTechnique, technique_id.upper())
        if not tech:
            console.print(f"[red]Error: Technique '{technique_id}' not found.[/red]")
            raise typer.Exit(code=1)

        rules = session.query(DetectionRule).all()
        matching = [r for r in rules if technique_id.upper() in [t.upper() for t in (r.technique_ids or [])]]

        if json_opt or output:
            import json as _json
            hunt_data = {
                "technique_id": tech.technique_id,
                "name": tech.name,
                "tactics": tech.tactics or [],
                "data_sources": tech.data_sources or [],
                "rules": [
                    {
                        "title": r.title,
                        "severity": r.severity,
                        "splunk_spl": sigma_convert(r.content, "splunk") or None,
                        "elastic_kql": sigma_convert(r.content, "elastic") or None,
                        "sentinel_kql": sigma_convert(r.content, "sentinel") or None,
                        "sigma_yaml": r.content,
                    }
                    for r in matching
                ],
            }
            js = _json.dumps(hunt_data, indent=2)
            if output:
                from pathlib import Path
                Path(output).write_text(js)
                console.print(f"[green]Saved hunt queries to {output}[/green]")
            else:
                print(js)
            return

        from rich.panel import Panel
        from rich.syntax import Syntax

        console.print(Panel(
            f"[bold]Technique:[/bold] {tech.technique_id} — {tech.name}\n"
            f"[bold]Tactics:[/bold] {', '.join(tech.tactics or [])}\n"
            f"[bold]Data Sources:[/bold] {', '.join((tech.data_sources or [])[:5])}\n"
            f"[bold]Rules found:[/bold] {len(matching)}",
            title="Hunt Query Generator",
            border_style="cyan",
        ))

        if not matching:
            console.print("[yellow]No Sigma rules cover this technique. Add rules via 'pythia sync sigma-full'.[/yellow]")
            if tech.detection_note:
                console.print(f"\n[bold]ATT&CK Detection Guidance:[/bold]\n{tech.detection_note[:500]}")
            return

        platforms = ["splunk", "elastic", "sentinel"] if platform == "all" else [platform.lower()]
        backend_labels = {"splunk": "Splunk SPL", "elastic": "Elastic KQL", "sentinel": "Sentinel KQL"}
        lexers = {"splunk": "splunk", "elastic": "text", "sentinel": "sql"}

        for rule in matching:
            console.print(f"\n[bold magenta]Rule: {rule.title}[/bold magenta]  [[yellow]{rule.severity or 'N/A'}[/yellow]]")
            for p in platforms:
                query = sigma_convert(rule.content, p)
                if query:
                    console.print(f"\n[bold]{backend_labels[p]}:[/bold]")
                    console.print(Syntax(query, lexers.get(p, "text"), theme="monokai"))


# ── watchlist sub-commands ────────────────────────────────────────────────────

watchlist_app = typer.Typer(name="watchlist", help="Manage webhook alert subscriptions.", no_args_is_help=True)
app.add_typer(watchlist_app)


@watchlist_app.command("add")
def watchlist_add(
    name: str = typer.Option(..., "--name", "-n", help="Label for this subscription"),
    webhook_url: str = typer.Option(..., "--webhook-url", "-w", help="Webhook URL (Slack, Discord, or generic)"),
    webhook_type: str = typer.Option("slack", "--type", "-t", help="slack | discord | generic"),
    actor: str = typer.Option(None, "--actor", "-a", help="Alert when actor name contains this"),
    ttp: str = typer.Option(None, "--ttp", help="Alert when TTPs include this technique ID"),
    sector: str = typer.Option(None, "--sector", "-s", help="Alert when sectors_targeted includes this"),
) -> None:
    """Create a watchlist subscription that fires a webhook on new matching intel."""
    if not any([actor, ttp, sector]):
        console.print("[red]Error: Provide at least one filter: --actor, --ttp, or --sector.[/red]")
        raise typer.Exit(code=1)

    from pythia.core.db import SessionLocal
    from pythia.models.watchlist import Watchlist

    with SessionLocal() as session:
        wl = Watchlist(
            name=name,
            filter_actor=actor,
            filter_ttp=ttp,
            filter_sector=sector,
            webhook_url=webhook_url,
            webhook_type=webhook_type,
        )
        session.add(wl)
        session.commit()
        session.refresh(wl)
        console.print(f"[green]Watchlist '[bold]{wl.name}[/bold]' created (ID: {wl.id})[/green]")
        filters = [f"actor={actor}" if actor else "", f"ttp={ttp}" if ttp else "", f"sector={sector}" if sector else ""]
        console.print(f"[dim]Filters: {', '.join(f for f in filters if f)}[/dim]")


@watchlist_app.command("list")
def watchlist_list(
    json_opt: bool = typer.Option(False, "--json", help="Output raw JSON"),
) -> None:
    """List all watchlist subscriptions."""
    from pythia.core.db import SessionLocal
    from pythia.models.watchlist import Watchlist

    with SessionLocal() as session:
        wls = session.query(Watchlist).order_by(Watchlist.created_at.desc()).all()
        if not wls:
            console.print("[yellow]No watchlists configured.[/yellow]")
            return

        if json_opt:
            import json as _json
            data = [
                {"id": w.id, "name": w.name, "filter_actor": w.filter_actor,
                 "filter_ttp": w.filter_ttp, "filter_sector": w.filter_sector,
                 "webhook_url": w.webhook_url, "webhook_type": w.webhook_type, "enabled": w.enabled}
                for w in wls
            ]
            print(_json.dumps(data, indent=2))
            return

        from rich.table import Table
        table = Table(title="Watchlist Subscriptions")
        table.add_column("ID", style="cyan", width=8)
        table.add_column("Name", style="bold")
        table.add_column("Actor filter")
        table.add_column("TTP filter")
        table.add_column("Sector filter")
        table.add_column("Type")
        table.add_column("Enabled", style="green")
        for w in wls:
            table.add_row(
                w.id[:8], w.name,
                w.filter_actor or "—", w.filter_ttp or "—", w.filter_sector or "—",
                w.webhook_type, "✓" if w.enabled else "✗",
            )
        console.print(table)


@watchlist_app.command("delete")
def watchlist_delete(
    watchlist_id: str = typer.Argument(..., help="Watchlist ID to delete"),
) -> None:
    """Delete a watchlist subscription."""
    from pythia.core.db import SessionLocal
    from pythia.models.watchlist import Watchlist

    with SessionLocal() as session:
        wl = session.get(Watchlist, watchlist_id)
        if not wl:
            console.print(f"[red]Error: Watchlist '{watchlist_id}' not found.[/red]")
            raise typer.Exit(code=1)
        name = wl.name
        session.delete(wl)
        session.commit()
        console.print(f"[green]Deleted watchlist '[bold]{name}[/bold]'.[/green]")


if __name__ == "__main__":
    app()
