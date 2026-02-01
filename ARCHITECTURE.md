# Architecture Technique - Security Scanner

## Vue d'ensemble

Le Security Scanner est une application web Flask conçue selon une architecture modulaire et sécurisée, respectant les principes de séparation des responsabilités et de défense en profondeur.

## Structure du projet

```
security_scanner/
│
├── app.py                          # Point d'entrée Flask (API REST)
│
├── scanner/                        # Module de scanning (logique métier)
│   ├── __init__.py                # Initialisation du package
│   ├── port_scanner.py            # Scan de ports TCP
│   ├── service_detector.py        # Détection de services
│   └── config_checks.py           # Analyse de sécurité
│
├── templates/                      # Templates HTML (présentation)
│   └── index.html                 # Interface utilisateur
│
├── static/                         # Ressources statiques
│   └── style.css                  # Feuille de style
│
├── test_scanner.py                # Tests unitaires
├── config_example.py              # Configuration de production
├── requirements.txt               # Dépendances Python
├── run.sh                         # Script de démarrage
│
└── Documentation/
    ├── README.md                  # Documentation utilisateur
    ├── CONTRIBUTING.md            # Guide de contribution
    ├── LICENSE                    # Licence MIT
    └── ARCHITECTURE.md            # Ce fichier
```

## Architecture logique

### Couche présentation (Frontend)

**Fichiers:** `templates/index.html`, `static/style.css`

**Responsabilités:**
- Interface utilisateur web responsive (Bootstrap 5)
- Validation côté client (JavaScript)
- Affichage des résultats avec code couleur par sévérité
- Communication AJAX avec le backend

**Choix techniques:**
- Bootstrap 5 : Framework CSS moderne et accessible
- JavaScript vanilla : Pas de dépendances lourdes
- Fetch API : Communication asynchrone avec le serveur
- Protection XSS : Échappement HTML dans le rendu

### Couche application (Backend)

**Fichier:** `app.py`

**Responsabilités:**
- Routage HTTP (Flask)
- Validation des entrées utilisateur
- Orchestration des modules de scanning
- Gestion des erreurs et logging
- Génération de réponses JSON

**Sécurité:**
- Validation stricte des paramètres
- Sanitization des entrées
- Rate limiting (recommandé en production)
- Audit logging de toutes les scans
- Gestion sécurisée des exceptions

### Couche métier (Scanner Modules)

#### 1. Port Scanner (`scanner/port_scanner.py`)

**Approche technique:**
- Scan TCP concurrent via ThreadPoolExecutor
- Socket timeout configurable
- Détection d'état: ouvert/fermé/filtré

**Considérations de performance:**
- Pool de threads limité (50 par défaut)
- Timeout court (1s) pour éviter les blocages
- Gestion gracieuse des erreurs réseau

**Sécurité:**
- Connexions TCP standard (pas de SYN flood)
- Validation de plage de ports (1-65535)
- Logging des tentatives de connexion

#### 2. Service Detector (`scanner/service_detector.py`)

**Techniques d'identification:**
- Banner grabbing passif (recv only)
- Regex pour parsing de versions
- Mapping ports IANA comme fallback

**Services détectés:**
- SSH, HTTP/HTTPS, FTP, SMTP
- Bases de données (MySQL, PostgreSQL, MongoDB, Redis)
- Services système (Telnet, RDP, SMB, VNC)

**Limites volontaires:**
- Pas d'envoi de probes actives (sauf HEAD HTTP minimal)
- Timeout court pour éviter DoS accidentel
- Gestion des encodages non-UTF8

#### 3. Configuration Checker (`scanner/config_checks.py`)

**Catégories d'analyse:**

1. **Protocoles non sécurisés**
   - Telnet (texte clair)
   - FTP (credentials en clair)
   - HTTP (vs HTTPS)

2. **Versions vulnérables**
   - Base de données CVE simplifiée
   - Détection de versions EOL
   - Références CVE pour recherche approfondie

3. **Services à risque exposés**
   - Bases de données accessibles
   - RDP/VNC exposés
   - SMB ouvert (ransomware risk)

4. **Divulgation d'information**
   - Banners trop verbeux
   - Versions exactes exposées

**Système de sévérité:**
- CRITICAL: Action immédiate requise
- HIGH: Risque significatif
- MEDIUM: Amélioration recommandée
- LOW: Durcissement optionnel

## Flux de données

```
┌─────────────┐
│  Utilisateur │
└──────┬──────┘
       │ 1. Saisie paramètres (IP, ports)
       ↓
┌──────────────────┐
│  index.html      │
│  (Frontend)      │
└──────┬───────────┘
       │ 2. POST /scan (JSON)
       ↓
┌──────────────────┐
│  app.py          │
│  (Flask Router)  │
└──────┬───────────┘
       │ 3. Validation
       ↓
┌──────────────────────────┐
│  PortScanner             │
│  → scan() → [22,80,443]  │
└──────┬───────────────────┘
       │ 4. Ports ouverts
       ↓
┌──────────────────────────┐
│  ServiceDetector         │
│  → detect_services()     │
└──────┬───────────────────┘
       │ 5. Services identifiés
       ↓
┌──────────────────────────┐
│  ConfigurationChecker    │
│  → check_configurations()│
└──────┬───────────────────┘
       │ 6. Alertes de sécurité
       ↓
┌──────────────────┐
│  app.py          │
│  (JSON Response) │
└──────┬───────────┘
       │ 7. Résultats JSON
       ↓
┌──────────────────┐
│  index.html      │
│  (Display)       │
└──────┬───────────┘
       │ 8. Affichage visuel
       ↓
┌─────────────┐
│  Utilisateur │
└─────────────┘
```

## Principes de conception

### 1. Séparation des responsabilités (SoC)

Chaque module a une responsabilité unique et clairement définie:
- `port_scanner`: Détection de ports UNIQUEMENT
- `service_detector`: Identification de services UNIQUEMENT
- `config_checks`: Analyse de sécurité UNIQUEMENT
- `app.py`: Orchestration et HTTP UNIQUEMENT

### 2. Défense en profondeur

Plusieurs couches de sécurité:
- **Validation frontend**: Première ligne (UX)
- **Validation backend**: Barrière critique
- **Logging**: Audit trail complet
- **Error handling**: Pas de stack traces exposées
- **Timeouts**: Protection DoS

### 3. Fail-safe defaults

Configuration par défaut sécurisée:
- Scan limité (1-1000) par défaut
- Timeout court (1s)
- Thread pool limité (50)
- Localhost only binding
- Debug mode OFF en production

### 4. Principe du moindre privilège

- Pas de root requis
- Scan passif uniquement
- Lecture seule sur réseau
- Logging non-privilégié

### 5. Transparence et auditabilité

- Tous les scans sont loggés
- Format de log structuré
- Timestamp sur chaque action
- Cible et paramètres enregistrés

## Choix techniques justifiés

### Pourquoi Flask ?

- **Léger**: Pas de overhead pour une application simple
- **Flexible**: Facile à étendre avec plugins
- **Standard**: Largement connu et documenté
- **Sécurisé**: Bonne gestion CSRF, XSS avec Jinja2

### Pourquoi pas Nmap/Masscan ?

- **Pédagogique**: Comprendre les fondamentaux
- **Contrôle**: Maîtrise complète du comportement
- **Portable**: Pas de dépendance système
- **Éthique**: Pas d'outils "offensifs"

### Pourquoi ThreadPoolExecutor ?

- **Performance**: Scan concurrent efficace
- **Simplicité**: API Python standard
- **Contrôle**: Limite de ressources claire
- **Sécurité**: Pas de race conditions (GIL)

### Pourquoi pas exploitation ?

**Philosophie du projet:**
- Outil **défensif** et **éducatif**
- Respect de l'**éthique** en cybersécurité
- **Légalité** par design
- **Portfolio professionnel** crédible

## Extensibilité

### Ajout d'un nouveau check de sécurité

```python
# Dans config_checks.py

def _check_nouvelle_vulnerabilite(self, service: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Description du nouveau check.
    
    Args:
        service: Informations du service
        
    Returns:
        List[Dict]: Alertes générées
    """
    alerts = []
    
    # Logique de détection
    if condition_vulnerabilite:
        alerts.append({
            'severity': 'HIGH',
            'title': 'Titre de l\'alerte',
            'description': 'Description détaillée',
            'recommendation': 'Actions correctives',
            'port': service['port'],
            'service': service['service']
        })
    
    return alerts
```

Puis appeler dans `check_configurations()`.

### Ajout d'un nouveau service

```python
# Dans service_detector.py

# 1. Ajouter au mapping COMMON_SERVICES
COMMON_SERVICES = {
    # ...
    8888: 'MonNouveauService'
}

# 2. Ajouter la détection dans _parse_service_info
elif 'nouveau_pattern' in banner_lower:
    service_info['service'] = 'MonNouveauService'
    # Parser la version si possible
```

## Limitations connues

### Techniques

- **Pas d'UDP**: Scan TCP uniquement
- **Pas d'IPv6**: Support IPv4 uniquement
- **Banner grabbing limité**: Certains services ne répondent pas
- **CVE database statique**: Pas de mise à jour automatique

### Performance

- **Scan séquentiel des services**: Pas de parallélisation
- **Timeout fixe**: Peut rater certains services lents
- **Thread pool limité**: Trade-off performance/ressources

### Sécurité

- **Pas d'authentification**: Interface locale seulement
- **Pas de rate limiting natif**: À ajouter en production
- **Logs en clair**: Pas de chiffrement des logs

## Améliorations futures

### Court terme
1. Support IPv6
2. Scan UDP
3. Export PDF/JSON des résultats
4. Historique des scans

### Moyen terme
1. Intégration CVE API (NVD)
2. Détection SSL/TLS avancée
3. Multi-cibles simultanées
4. Dashboard avec graphiques

### Long terme
1. Mode headless/CLI
2. Plugins tiers
3. Intégration SIEM
4. Scan planifiés (cron-like)

## Considérations de déploiement

### Développement
```bash
python app.py
# http://localhost:5000
```

### Production
```bash
# Avec Gunicorn
gunicorn -w 4 -b 127.0.0.1:5000 app:app

# Avec reverse proxy Nginx
# Voir nginx.conf.example
```

### Docker (futur)
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

## Conclusion

Cette architecture privilégie:
- ✅ **Clarté** sur complexité
- ✅ **Sécurité** par design
- ✅ **Maintenabilité** à long terme
- ✅ **Extensibilité** pour évolutions futures
- ✅ **Éthique** en cybersécurité

Le code est conçu pour être lu, compris, et évalué par des recruteurs techniques tout en restant un outil fonctionnel pour des audits de sécurité légitimes.
