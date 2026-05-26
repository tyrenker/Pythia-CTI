#!/usr/bin/env python3
"""
Preload and enrich the Pythia database with community-sourced threat intelligence
from the famous 'APT Groups, Operations and Tactics' Google Sheet.

Usage:
    PYTHONPATH=src python3 scripts/import_apt_sheet.py [--dry-run] [--reset]
"""

from __future__ import annotations

import argparse
import csv
import io
import re
import sys
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pythia.core.db import SessionLocal, init_db
from pythia.models.actor import ThreatActor

# Rich console formatting
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
    from rich.table import Table
    console = Console()
except ImportError:
    # Fallback to plain printing if rich is missing (though it is in pyproject.toml)
    class DummyConsole:
        def print(self, *args, **kwargs):
            text = " ".join(str(a) for a in args)
            # Remove rich tags
            text = re.sub(r'\[/?\w+.*?\]', '', text)
            print(text)
    console = DummyConsole()  # type: ignore

# Country and Sheet GID configurations
TABS = {
    "China": ("361554658", "CN", "nation-state"),
    "Russia": ("1636225066", "RU", "nation-state"),
    "North Korea": ("1905351590", "KP", "nation-state"),
    "Iran": ("376438690", "IR", "nation-state"),
    "Israel": ("300065512", "IL", "nation-state"),
    "NATO": ("2069598202", None, "nation-state"),
    "Middle East": ("574287636", None, "nation-state"),
    "Others": ("438782970", None, "unknown"),
    "Unknown": ("1121522397", None, "unknown"),
}

SPONSOR_KEYWORDS = {
    "nation-state": ["nation-state", "nation state", "government", "apt", "state-sponsored", "mil", "military"],
    "financially-motivated": ["financial", "criminal", "ransomware", "cybercriminal", "profit", "money", "extortion"],
    "hacktivist": ["hacktivist", "activism", "ideolog", "pro-russian", "pro-ukrainian", "leak"],
}

def infer_sponsor(text: str, default: str) -> str:
    """Infer actor sponsor type using target and description keywords."""
    text_lower = text.lower()
    for sponsor, keywords in SPONSOR_KEYWORDS.items():
        if any(k in text_lower for k in keywords):
            return sponsor
    return default or "unknown"

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ingest threat actors from the decalage APT spreadsheet.")
    parser.add_argument("--dry-run", action="store_true", help="Parse and log what would change without modifying the database.")
    parser.add_argument("--reset", action="store_true", help="Remove previously imported APT spreadsheet data before running.")
    return parser.parse_args()

def fetch_sheet_tab(gid: str) -> list[list[str]] | None:
    """Download a spreadsheet tab as CSV from the public Google Sheet URL."""
    url = f"https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/export?format=csv&gid={gid}"
    req = urllib.request.Request(
        url,
        headers={'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            content = response.read().decode('utf-8')
            csv_file = io.StringIO(content)
            reader = csv.reader(csv_file)
            return list(reader)
    except Exception as e:
        console.print(f"[red]Error downloading sheet tab (GID: {gid}): {e}[/red]")
        return None

def import_tab(session: Any, tab_name: str, gid: str, country_code: str | None, default_sponsor: str, dry_run: bool) -> dict[str, int]:
    rows = fetch_sheet_tab(gid)
    if not rows or len(rows) < 3:
        console.print(f"[yellow]Skipping tab '{tab_name}': empty or invalid format.[/yellow]")
        return {"added": 0, "enriched": 0, "skipped": 0}

    # Row 0: Title, Row 1: Headers
    headers = [h.strip() for h in rows[1]]
    data_rows = rows[2:]

    # Map column headers to discover where data lies dynamically
    alias_cols = []
    mitre_idx = -1
    targets_idx = -1
    mo_idx = -1
    comment_idx = -1
    link_cols = []

    alias_keywords = [
        "name", "alias", "crowdstrike", "irl", "kaspersky", "secureworks", 
        "mandiant", "fireeye", "symantec", "isight", "cisco", "talos", 
        "palo alto", "unit 42", "unit42", "dell secure works", "talos group", "nsa"
    ]

    for idx, h in enumerate(headers):
        h_lower = h.lower()
        if idx == 0:
            continue  # Column 0 is always Common Name

        if "mitre" in h_lower:
            mitre_idx = idx
        elif "target" in h_lower:
            targets_idx = idx
        elif "modus" in h_lower or "description" in h_lower:
            mo_idx = idx
        elif "comment" in h_lower:
            comment_idx = idx
        elif "link" in h_lower:
            link_cols.append(idx)
        elif any(kw in h_lower for kw in alias_keywords):
            alias_cols.append(idx)

    stats = {"added": 0, "enriched": 0, "skipped": 0}

    for row in data_rows:
        if not row or not row[0].strip() or row[0].strip() == "Common Name":
            continue

        common_name = row[0].strip()
        
        # 1. Clean actor name
        common_name = re.sub(r'\s+Group$', '', common_name)  # Clean up "Lazarus Group" -> "Lazarus" or keep it consistent
        common_name = common_name.strip()

        # 2. Extract aliases
        aliases = []
        for col_idx in alias_cols:
            if col_idx < len(row):
                val = row[col_idx].strip()
                if val and val.lower() != "n/a" and val.lower() != "none" and val != common_name:
                    # Handle multiple aliases separated by commas/slashes
                    parts = [p.strip() for p in re.split(r'[,/]', val)]
                    for p in parts:
                        # Clean inner parentheses and whitespace
                        p_clean = re.sub(r'\s*\([^)]*\)', '', p).strip()
                        if p_clean and p_clean not in aliases and p_clean != common_name:
                            aliases.append(p_clean)

        # 3. Extract MITRE ATT&CK Group ID
        mitre_id = None
        if mitre_idx != -1 and mitre_idx < len(row):
            mitre_val = row[mitre_idx].strip()
            m = re.search(r'G\d{4}', mitre_val)
            if m:
                mitre_id = m.group(0)

        # 4. Modus Operandi & Comments -> Description
        mo_val = row[mo_idx].strip() if mo_idx != -1 and mo_idx < len(row) else ""
        comment_val = row[comment_idx].strip() if comment_idx != -1 and comment_idx < len(row) else ""
        desc_parts = []
        if mo_val and mo_val.lower() != "n/a":
            desc_parts.append(mo_val)
        if comment_val and comment_val.lower() != "n/a":
            desc_parts.append(f"Note: {comment_val}")
        description = "\n\n".join(desc_parts) if desc_parts else None

        # 5. Target Sectors
        sectors = []
        if targets_idx != -1 and targets_idx < len(row):
            target_val = row[targets_idx].strip()
            if target_val and target_val.lower() != "n/a":
                # Split targeted entities
                sectors = [t.strip() for t in re.split(r'[,;•\n]', target_val) if t.strip()]

        # 6. References
        links = []
        for col_idx in link_cols:
            if col_idx < len(row):
                val = row[col_idx].strip()
                if val.startswith("http"):
                    links.append(val)
        for cell in row:
            if cell.strip().startswith("http") and cell.strip() not in links:
                links.append(cell.strip())

        # Determine sponsor type
        combined_text = f"{common_name} {' '.join(aliases)} {description or ''} {' '.join(sectors)}"
        sponsor_type = infer_sponsor(combined_text, default_sponsor)

        # Check for existing actor (by name or MITRE ID)
        existing = None
        if mitre_id:
            existing = session.query(ThreatActor).filter_by(attck_group_id=mitre_id).first()
        if not existing:
            existing = session.query(ThreatActor).filter(ThreatActor.name.ilike(common_name)).first()
        if not existing and aliases:
            # Check if common name matches one of the existing aliases
            for alias in aliases:
                existing = session.query(ThreatActor).filter(ThreatActor.aliases.like(f'%"{alias}"%')).first()
                if existing:
                    break

        if existing:
            # ENRICH existing record (from MISP/MITRE)
            if dry_run:
                stats["enriched"] += 1
                continue

            # Merge aliases
            existing_aliases = set(existing.aliases or [])
            for alias in aliases:
                existing_aliases.add(alias)
            existing.aliases = list(existing_aliases)

            # Merge description (append if different)
            if description and description not in (existing.description or ""):
                if existing.description:
                    existing.description += f"\n\n[APT Sheet Description]\n{description}"
                else:
                    existing.description = description

            # Merge target sectors
            existing_sectors = set(existing.sectors_targeted or [])
            for s in sectors:
                # Clean up sector strings a bit (skip geographic strings that might slip in)
                if len(s) < 50 and not any(country.lower() in s.lower() for country in ["korea", "china", "vietnam", "russia", "usa", "europe", "japan"]):
                    existing_sectors.add(s)
            existing.sectors_targeted = list(existing_sectors)

            # Merge references
            existing_refs = set(existing.references or [])
            for link in links:
                existing_refs.add(link)
            existing.references = list(existing_refs)

            # Enrich structural fields if they were missing
            if country_code and not existing.country_code:
                existing.country_code = country_code
            if not existing.attck_group_id and mitre_id:
                existing.attck_group_id = mitre_id
            if existing.sponsor_type == "unknown" and sponsor_type != "unknown":
                existing.sponsor_type = sponsor_type

            stats["enriched"] += 1
        else:
            # CREATE new record
            if dry_run:
                stats["added"] += 1
                continue

            # Filter targeted sectors
            clean_sectors = [s for s in sectors if len(s) < 50 and not any(c.lower() in s.lower() for c in ["korea", "china", "vietnam", "russia", "usa", "europe", "japan"])]

            actor = ThreatActor(
                name=common_name,
                aliases=aliases,
                description=description,
                country_code=country_code,
                sponsor_type=sponsor_type,
                motivations=[],
                sectors_targeted=clean_sectors,
                geographies_targeted=[country_code] if country_code else [],
                references=links,
                tlp="WHITE",
                attck_group_id=mitre_id,
                source="apt-spreadsheet",
                source_url=f"https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/pubhtml#gid={gid}"
            )
            session.add(actor)
            stats["added"] += 1

    if not dry_run:
        session.commit()

    return stats

def main() -> None:
    args = parse_args()
    
    console.print("[bold cyan]Pythia APT Spreadsheet Importer[/bold cyan]")
    console.print(f"Source: [underline]https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU[/underline]")
    if args.dry_run:
        console.print("[bold yellow]Running in DRY-RUN mode — no database modifications will be written.[/bold yellow]")
    
    # Initialize DB (creates tables if missing)
    if not args.dry_run:
        init_db()

    session = SessionLocal()
    
    try:
        # Handle reset option
        if args.reset and not args.dry_run:
            console.print("\n[bold red]Resetting APT Spreadsheet Data...[/bold red]")
            deleted = session.query(ThreatActor).filter_by(source="apt-spreadsheet").delete()
            session.commit()
            console.print(f"[green]✓ Removed {deleted} previously imported 'apt-spreadsheet' actors.[/green]")
        
        results = []
        total_added = 0
        total_enriched = 0
        
        console.print("\n[bold cyan]Downloading and processing country tabs...[/bold cyan]")
        
        # Use rich progress bar if available
        if 'Progress' in globals():
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]Processing tabs...", total=len(TABS))
                
                for tab_name, (gid, country, sponsor) in TABS.items():
                    progress.update(task, description=f"[cyan]Ingesting {tab_name}...")
                    stats = import_tab(session, tab_name, gid, country, sponsor, args.dry_run)
                    results.append((tab_name, stats))
                    total_added += stats["added"]
                    total_enriched += stats["enriched"]
                    progress.advance(task)
        else:
            # Fallback plain logging
            for tab_name, (gid, country, sponsor) in TABS.items():
                print(f"Ingesting {tab_name} (gid={gid})...")
                stats = import_tab(session, tab_name, gid, country, sponsor, args.dry_run)
                results.append((tab_name, stats))
                total_added += stats["added"]
                total_enriched += stats["enriched"]
        
        # Print summary table
        table = Table(title="\nIngestion Summary", border_style="cyan")
        table.add_column("Tab Name", style="bold white")
        table.add_column("Actors Created", style="green", justify="right")
        table.add_column("Actors Enriched", style="yellow", justify="right")
        
        for tab_name, stats in results:
            table.add_row(tab_name, str(stats["added"]), str(stats["enriched"]))
            
        table.add_row("TOTALS", f"[bold green]{total_added}[/bold green]", f"[bold yellow]{total_enriched}[/bold yellow]")
        console.print(table)
        
        console.print(f"\n[bold green]✓ Done! Total Processed: {total_added} created, {total_enriched} enriched.[/bold green]")
        
    except KeyboardInterrupt:
        console.print("[red]\nOperation aborted by user.[/red]")
        sys.exit(1)
    finally:
        session.close()

if __name__ == "__main__":
    main()
