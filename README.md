# **🔍 Outil de Pentest Interactif - AI, Nuclei & Shodan**

![Pentest CLI](https://img.shields.io/badge/Pentest-CLI-blue?style=for-the-badge)  
Outil interactif de **pentest** combinant **Nuclei, Shodan, WaybackMachine et OpenAI** pour une analyse avancée d'un site web cible.  

## **📌 Fonctionnalités**
✅ **Scan de vulnérabilités avec Nuclei**  
✅ **Recherche d’informations via Shodan**  
✅ **Analyse des archives avec WaybackMachine**  
✅ **Évaluation des risques avec OpenAI AI**  
✅ **Exécution parallèle ultra rapide (async)**  
✅ **Affichage interactif avec `rich`**  

---

## **🚀 Installation**
### **1️⃣ Cloner le projet**
```bash
git clone https://github.com/trhacknon/pentest-interactif.git
cd pentest-interactif
```

2️⃣ Installer les dépendances

```
pip install -r requirements.txt
```

3️⃣ Ajouter tes clés API

Crée un fichier .env et ajoute tes clés :

```json
OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
GROQ_API_KEY=gr-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
SHODAN_API_KEY=shodan-xxxxxxxxxxxxxxxxxxxxxxxxxx
```


---

🔧 Utilisation

Exécute simplement :

```
python3 main.py
```

Puis, saisis l’URL cible à analyser.

📜 Exemple de sortie

```bash
🛡️ Outil de pentest interactif
🌐 Entrez l'URL cible: example.com

🔍 Analyse en cours pour : example.com

✔ Résultats Nuclei :
- [CRITICAL] SQL Injection found at /login.php
- [HIGH] XSS Vulnerability at /search.php

✔ Résultats Shodan :
- Port 80 (Apache 2.4)
- Technologie : PHP 7.4, MySQL

📜 WaybackMachine :
- Archives trouvées : 2015, 2018, 2022

🤖 AI OpenAI :
- Ce site présente un risque élevé de SQLi et XSS
```

---

🛠 Modules utilisés

📌 [httpx] – Requêtes HTTP asynchrones
📌 [questionary] – Interface CLI interactive
📌 [rich] – Affichage coloré
📌 [asyncio] – Gestion des tâches asynchrones
📌 [dotenv] – Chargement des clés API
📌 [shodan] – Recherches sur Shodan
📌 [openai] – Analyse par IA
📌 [nuclei] – Scan de vulnérabilités
📌 [waybackpy] – Extraction d’archives


---

📜 Licence

Ce projet est fourni à des fins éducatives uniquement.
L’utilisation de cet outil sur un système sans autorisation est strictement interdite ⚠️.

