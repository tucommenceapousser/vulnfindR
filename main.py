import os
import asyncio
import httpx
import questionary
import shodan
import subprocess
from censys.search import CensysHosts
from rich.console import Console
from rich.progress import track
from langchain_openai import OpenAI
from dotenv import load_dotenv
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Chargement des variables d'environnement
load_dotenv()
console = Console()

# Vérification des API Keys
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
CENSYS_API_ID = os.getenv("CENSYS_API_ID")
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET")

if not OPENAI_API_KEY or not GROQ_API_KEY or not SHODAN_API_KEY or not CENSYS_API_ID or not CENSYS_API_SECRET:
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
        return result.stdout
    except Exception as e:
        return f"❌ Erreur lors de l'exécution de Nuclei : {e}"

# Fonction pour scanner avec Shodan
async def scan_shodan(target):
    console.print("[blue]🌐 Recherche Shodan...[/blue]")
    try:
        shodan_api = shodan.Shodan(SHODAN_API_KEY)
        result = shodan_api.host(target)
        return str(result)
    except Exception as e:
        return f"❌ Erreur Shodan : {e}"

# Fonction pour scanner avec Censys
async def scan_censys(target):
    console.print("[cyan]🔍 Recherche Censys...[/cyan]")
    try:
        censys_client = CensysHosts(CENSYS_API_ID, CENSYS_API_SECRET)
        result = censys_client.view(target)
        return str(result)
    except Exception as e:
        return f"❌ Erreur Censys : {e}"

# Fonction pour récupérer des archives WaybackMachine
async def scan_wayback(target):
    console.print("[cyan]📜 Analyse WaybackMachine...[/cyan]")
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"http://web.archive.org/cdx/search/cdx?url={target}&output=json", timeout=30)
            if response.status_code == 200:
                return str(response.json())
            else:
                return "⚠ Aucune archive trouvée."
    except httpx.TimeoutException:
        return "⏳ Timeout lors de l'analyse WaybackMachine."

# Fonction d'analyse OpenAI
async def ai_analysis(target):
    console.print("[magenta]🤖 Analyse AI avec OpenAI...[/magenta]")
    llm = OpenAI(api_key=OPENAI_API_KEY)
    prompt = f"Quels sont les risques de sécurité pour le site {target} ?"
    response = llm.predict(prompt)
    return response

# Génération d’un rapport PDF
def generate_pdf(target, results):
    filename = f"rapport_{target.replace('.', '_')}.pdf"
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, height - 50, f"Rapport d'Analyse : {target}")

    c.setFont("Helvetica", 12)
    y = height - 100
    for key, value in results.items():
        c.drawString(50, y, f"🔹 {key} :")
        y -= 20
        c.drawString(70, y, value[:500])  # Afficher seulement une partie pour éviter un débordement
        y -= 40

    c.save()
    console.print(f"[green]📄 Rapport généré : {filename}[/green]")

# Fonction principale d'analyse
async def analyze_target(target):
    tasks = {
        "Nuclei": scan_nuclei(target),
        "Shodan": scan_shodan(target),
        "Censys": scan_censys(target),
        "WaybackMachine": scan_wayback(target),
        "OpenAI": ai_analysis(target),
    }
    results = await asyncio.gather(*tasks.values())

    final_results = dict(zip(tasks.keys(), results))

    # Génération du rapport PDF
    generate_pdf(target, final_results)

    for key, value in final_results.items():
        console.print(f"[bold cyan]{key}[/bold cyan] : {value[:500]}...\n")

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
