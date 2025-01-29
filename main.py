import os
import json
import httpx
import questionary
import asyncio
import concurrent.futures
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from langchain.llms import OpenAI

# Configuration API
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

console = Console()

# Liste des modules de scan
SCANNERS = ["headers", "shodan", "nuclei", "wayback", "openai_analysis"]

# Fonction pour scanner une URL avec HTTPX (rapide et performant)
async def fetch_url(url):
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(url)
            return {"url": url, "status": response.status_code, "content": response.text}
    except Exception as e:
        return {"url": url, "error": str(e)}

# Scanner Shodan pour voir les services actifs
async def scan_shodan(domain):
    url = f"https://api.shodan.io/shodan/host/{domain}?key={SHODAN_API_KEY}"
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        return response.json() if response.status_code == 200 else None

# Scanner Nuclei (détection de vulnérabilités)
async def scan_nuclei(url):
    cmd = f"echo '{url}' | nuclei -silent -json"
    result = os.popen(cmd).read()
    return json.loads(result) if result else None

# Scanner Wayback Machine pour voir les anciennes versions
async def scan_wayback(domain):
    url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=5"
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        return response.json() if response.status_code == 200 else None

# Scanner OpenAI pour obtenir des suggestions de vulnérabilités
def ai_suggestion(prompt):
    llm = OpenAI(api_key=OPENAI_API_KEY)
    return llm.predict(prompt)

# Analyse avancée avec plusieurs scanners en parallèle
async def analyze_target(url):
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]

    console.print(f"[bold cyan]🔍 Analyse en cours pour : {url}[/bold cyan]")

    # Multi-threading pour les tâches CPU-heavy
    with concurrent.futures.ThreadPoolExecutor() as executor:
        tasks = {
            "headers": fetch_url(url),
            "shodan": scan_shodan(domain),
            "nuclei": scan_nuclei(url),
            "wayback": scan_wayback(domain)
        }
        
        results = await asyncio.gather(*tasks.values())

    # Organiser les résultats
    scan_results = dict(zip(tasks.keys(), results))

    # Analyse avec OpenAI
    ai_prompt = f"Analyse de sécurité pour {url} avec ces résultats : {scan_results}. Quelles vulnérabilités potentielles ?"
    scan_results["openai_analysis"] = ai_suggestion(ai_prompt)

    return scan_results

# Affichage interactif des résultats
def display_results(results):
    table = Table(title="Résultats de l'analyse", show_lines=True)
    table.add_column("Module", justify="left", style="cyan", no_wrap=True)
    table.add_column("Résultat", justify="left", style="green")

    for key, value in results.items():
        result_str = json.dumps(value, indent=2) if isinstance(value, dict) else str(value)
        table.add_row(key, result_str[:100] + "..." if len(result_str) > 100 else result_str)

    console.print(table)

# Interface interactive
def main():
    console.print("[bold yellow]🛡️ Outil de pentest interactif[/bold yellow]\n")
    url = questionary.text("Entrez l'URL cible :").ask()

    # Exécuter l'analyse asynchrone
    results = asyncio.run(analyze_target(url))

    # Afficher les résultats
    display_results(results)

    # Sauvegarder en JSON
    with open("scan_results.json", "w") as f:
        json.dump(results, f, indent=4)

    console.print("[bold magenta]📁 Résultats sauvegardés dans scan_results.json[/bold magenta]")

if __name__ == "__main__":
    main()
