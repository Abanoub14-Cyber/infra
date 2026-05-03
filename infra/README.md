# INFRA — Infrastructure Intelligence Through Passive Observation

Outil d'audit réseau passif pour cartographier une infrastructure cliente sans
agent, sans configuration sur les machines, sans déchiffrement.

## ⚠️ Avertissement légal

Cet outil capture du trafic réseau. Selon votre juridiction, cela peut être
encadré par la loi (RGPD, Code pénal art. 323-1 en France, art. 550bis en
Belgique, etc.). **Avant utilisation chez un client :**

1. Obtenez un **mandat écrit** signé définissant le périmètre, la durée, et
   les types de données collectées.
2. Le mode `--gateway` (ARP spoofing) modifie activement le réseau et est
   considéré comme une technique d'attaque MITM. Ne l'utilisez **jamais**
   sans autorisation écrite explicite mentionnant cette technique.
3. Le fichier `infra.db` contient des métadonnées potentiellement sensibles
   (hostnames, MAC addresses, domaines visités). Stockez-le de manière
   sécurisée et supprimez-le selon la politique de rétention convenue.

## Installation

```bash
# Système
sudo apt install python3 python3-pip libpcap-dev

# Python deps
pip install -r requirements.txt
```

## Usage

```bash
# Capture passive (broadcasts + propre trafic uniquement, mode safe par défaut)
sudo python3 infra.py capture -i eth0

# Capture avec auto-stop après 8h
sudo python3 infra.py capture -i eth0 -t 8

# Mode gateway (ARP spoofing) — NÉCESSITE MANDAT ÉCRIT
sudo python3 infra.py capture -i eth0 --gateway

# Rejouer un PCAP au lieu de capturer (pour tests / audit déporté)
python3 infra.py replay capture.pcap

# Génération du rapport
python3 infra.py analyze              # JSON
python3 infra.py analyze --html       # JSON + HTML

# Statut d'une capture
python3 infra.py status

# Diff entre deux rapports
python3 infra.py diff report1.json report2.json
```

## Méthodes de capture par environnement

| Environnement | Méthode recommandée | Couverture |
|---|---|---|
| Switch managé | Port mirror (SPAN) → mode passif | 100% |
| Switch non managé | Mode gateway (avec mandat) | 100% |
| Wi-Fi infrastructure | Mode passif (limité) | ~10% |
| Wi-Fi monitor (clé partagée) | airmon-ng + mode passif | Variable |
| Audit déporté | Client envoie un PCAP → mode replay | Selon PCAP |

## Tests

```bash
# Tests unitaires des parsers (sans privilèges)
python3 -m pytest tests/

# Test d'intégration via PCAP
python3 infra.py replay tests/fixtures/sample.pcap
python3 infra.py analyze --db replay.db
```

## Architecture

- `infra/db.py` — SQLite avec WAL, connexion long-lived, batching
- `infra/parsers/` — Parsers protocoles (TLS/JA4, DHCP, mDNS, LLDP, DNS, IPv6)
- `infra/enrichment.py` — OUI lookup, cloud CIDR, SaaS, ports
- `infra/capture.py` — Capture engine
- `infra/gateway.py` — Mode ARP avec garde-fous + restoration
- `infra/replay.py` — Lecture PCAP
- `infra/intelligence.py` — Analyse (devices, SaaS, patterns, deps, anomalies)
- `infra/report.py` — Génération JSON + HTML

## Limitations connues

- TLS ClientHello fragmenté sur plusieurs segments TCP : non géré (~5% des cas)
- DNS-over-TCP, DNS-over-HTTPS : non détectés (par design — chiffrés)
- IPv6 extension headers (Hop-by-Hop, Fragment, Routing) : non parsés
- JA3 → JA4 : utilise JA4 par défaut (plus stable que JA3 face aux mises à jour navigateur)
- Wi-Fi infrastructure : ne capture que ses propres trames + broadcasts/multicasts
