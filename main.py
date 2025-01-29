import os
import asyncio
import httpx
import questionary
from rich.console import Console
from rich.progress import track
from langchain_openai import OpenAI
from dotenv import load_dotenv
import shodan
import subprocess

# Chargement des variables d'environnement
load_dotenv()
console = Console()

# Vérification des API Keys
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

if not OPENAI_API_KEY or not GROQ_API_KEY or not SHODAN_API_KEY:
    console.print("[red]🚨 Erreur : Clé API manquante ! Vérifie ton fichier .env[/red]")
    exit(1)

# Vérification des permissions Nuclei
NUCLEI_PATH = subprocess.run(["which", "nuclei"], capture_output=True, text=True).stdout.strip()
if NUCLEI_PATH:
    subprocess.run(["chmod", "+x", NUCLEI_PATH])

# Fonction pour scanner avec Nuclei
async def scan_nuclei(target):
    console.print("[yellow]🔍 Exécution de Nuclei...[/yellow]")
    try:
        result = subprocess.run(["nuclei", "-u", target], capture_output=True, text=True)
        console.print(f"[green]✔ Résultats Nuclei :[/green]\n{result.stdout}")
    except Exception as e:
        console.print(f"[red]❌ Erreur lors de l'exécution de Nuclei : {e}[/red]")

# Fonction pour scanner avec Shodan
async def scan_shodan(target):
    console.print("[blue]🌐 Recherche Shodan...[/blue]")
    try:
        shodan_api = shodan.Shodan(SHODAN_API_KEY)
        result = shodan_api.host(target)
        console.print(f"[green]✔ Résultats Shodan :[/green]\n{result}")
    except Exception as e:
        console.print(f"[red]❌ Erreur Shodan : {e}[/red]")

# Fonction pour récupérer des archives WaybackMachine
async def scan_wayback(target):
    console.print("[cyan]📜 Analyse WaybackMachine...[/cyan]")
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"http://web.archive.org/cdx/search/cdx?url={target}&output=json", timeout=30)
            if response.status_code == 200:
                console.print(f"[green]✔ Archives trouvées !\n{response.json()}[/green]")
            else:
                console.print("[yellow]⚠ Aucune archive trouvée.[/yellow]")
    except httpx.TimeoutException:
        console.print("[red]⏳ Timeout lors de l'analyse WaybackMachine.[/red]")

# Fonction d'analyse OpenAI
async def ai_analysis(target):
    console.print("[magenta]🤖 Analyse AI avec OpenAI...[/magenta]")
    llm = OpenAI(api_key=OPENAI_API_KEY)
    prompt = f"Quels sont les risques de sécurité pour le site {target} ?"
    response = llm.predict(prompt)
    console.print(f"[green]✔ Résultats AI :[/green]\n{response}")

# Fonction principale d'analyse
async def analyze_target(target):
    tasks = {
        "nuclei": scan_nuclei(target),
        "shodan": scan_shodan(target),
        "wayback": scan_wayback(target),
        "openai": ai_analysis(target)
    }
    await asyncio.gather(*tasks.values())

# Interface utilisateur
def main():
    console.print("[bold green]🛡️ Outil de pentest interactif[/bold green]")
    
    url = questionary.text("🌐 Entrez l'URL cible").ask()
    if not url:
        console.print("[red]⚠ Veuillez entrer une URL valide.[/red]")
        return
    
    console.print(f"[yellow]🔍 Analyse en cours pour : {url}[/yellow]")
    asyncio.run(analyze_target(url))

if __name__ == "__main__":
    main()
