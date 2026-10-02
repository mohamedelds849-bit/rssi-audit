# LEARN : comprendre chaque contrôle (et le défendre en entretien)

Ce document explique **comment fonctionne chaque vérification** de l'outil, **ce qu'elle
protège**, et **où sont ses limites**. Il se termine par 15 questions d'entretien avec des
réponses modèles courtes.

---

## 1. SSL/TLS (`modules/ssl_headers.py`)

**Ce que fait le code** : ouverture d'une connexion TCP sur le port 443, puis d'une poignée de
main TLS (`ssl.create_default_context(cafile=certifi.where())` + `wrap_socket(server_hostname=...)`). Le SNI
(`server_hostname`) indique au serveur quel certificat présenter.

| Contrôle | Comment | Pourquoi c'est important |
|---|---|---|
| Validation de la chaîne | Python vérifie signature par signature : feuille → intermédiaire(s) → racine de confiance. On utilise le magasin de racines **Mozilla (certifi)** pour avoir le même résultat sur toutes les machines. | Une chaîne cassée = avertissement navigateur, perte de confiance, et parfois des clients (apps mobiles, API) qui refusent de se connecter. |
| Expiration | Lecture du champ `notAfter` ; seuils : expiré = critique, < 15 j = élevé, < 30 j = moyen. | Un certificat expiré coupe pratiquement le site. Le seuil laisse le temps de réagir si le renouvellement automatique est cassé. |
| Concordance du nom | Comparaison du domaine avec le CN et les SAN (DNS). `*.exemple.com` couvre `www.exemple.com` mais **ni** `exemple.com` **ni** `a.b.exemple.com`. | Un nom qui ne correspond pas = alerte navigateur ; c'est aussi le signe d'une configuration d'hébergement mutualisé mal faite. |
| Version du protocole | `ssock.version()` ; SSLv2/v3, TLS 1.0/1.1 = échec. | Ces versions ont des faiblesses connues (POODLE, BEAST, chiffrements faibles) et sont abandonnées par les navigateurs (RFC 8996). |

**Cas particulier** : si la validation échoue, on refait une connexion **sans validation**
(`_create_unverified_context`) uniquement pour **lire** le certificat et distinguer
« pas de HTTPS du tout » / « certificat invalide » / « feuille valide mais chaîne cassée ».

**Leçon apprise sur rotaskitchen.com** : avec le magasin de certificats Windows, Python
renvoyait *certificate has expired* alors que `openssl s_client` et `curl` validaient la
chaîne. Cause : une ancienne racine/intermédiaire expirée dans le magasin local. D'où le
passage à certifi. Morale : **toujours confirmer un résultat surprenant avec un second
outil** avant de le mettre dans un rapport.

## 2. En-têtes HTTP de sécurité

Une seule requête GET sur la page d'accueil (`utils.fetch_url`), puis lecture des en-têtes.

| En-tête | Protège contre | Valeur recommandée |
|---|---|---|
| `Strict-Transport-Security` (HSTS) | **Downgrade / SSL stripping** : un attaquant sur un Wi-Fi public force la version HTTP. Avec HSTS, le navigateur refuse le HTTP pour ce domaine pendant `max-age`. | `max-age=31536000; includeSubDomains` (+ `preload` si maîtrisé) |
| `Content-Security-Policy` (CSP) | **XSS** et injection de contenu : liste blanche des sources de scripts, styles, iframes… Un script injecté d'une origine non autorisée n'est pas exécuté. | `default-src 'self'; script-src 'self' ...; frame-ancestors 'self'` (commencer en `Report-Only`) |
| `X-Frame-Options` | **Clickjacking** : le site est chargé dans une iframe invisible et la victime clique sans le savoir. | `SAMEORIGIN` ou `DENY` (équivalent moderne : CSP `frame-ancestors`) |
| `X-Content-Type-Options` | **MIME sniffing** : le navigateur « devine » qu'un fichier texte est un script et l'exécute. | `nosniff` |
| `Referrer-Policy` | **Fuite d'URL** vers des sites tiers (jetons dans l'URL, pages privées). | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | Abus des API sensibles du navigateur (caméra, micro, géolocalisation) par des scripts/iframes tiers. | `camera=(), microphone=(), geolocation=()` |
| `Server` / `X-Powered-By` | **Reconnaissance** : la version exacte aide l'attaquant à choisir son exploit. | Masquer (`ServerTokens Prod`, `server_tokens off`, `expose_php = Off`) |

On teste aussi `http://domaine` : si l'URL finale est en `https://`, la redirection est en
place.

**Limite** : l'outil vérifie la **présence** d'un en-tête, pas sa **qualité**. Une CSP
`upgrade-insecure-requests` « passe » alors qu'elle ne protège pas du XSS.

## 3. Email : SPF, DKIM, DMARC, MX (`modules/email_dns.py`)

Le problème de départ : le protocole SMTP **ne vérifie pas l'expéditeur**. N'importe qui
peut écrire `From: direction@votre-pme.ma`. Trois mécanismes DNS corrigent cela.

### SPF (Sender Policy Framework, RFC 7208)
- Enregistrement **TXT sur le domaine** : `v=spf1 include:_spf.google.com -all`.
- Il liste **les serveurs autorisés à envoyer** pour le domaine. Le serveur destinataire
  compare l'IP de l'expéditeur (enveloppe `MAIL FROM`) à cette liste.
- Le qualificateur final décide du sort des autres : `-all` = rejet (strict), `~all` =
  softfail (marqué, souvent accepté), `?all` = neutre, `+all` = tout le monde autorisé
  (catastrophique).
- Limites : SPF vérifie l'enveloppe, pas l'en-tête `From:` visible ; il casse avec le
  transfert d'email ; maximum 10 requêtes DNS (`include`, `a`, `mx`…).

### DKIM (DomainKeys Identified Mail, RFC 6376)
- Le serveur d'envoi **signe** certains en-têtes + le corps avec une **clé privée**.
- La **clé publique** est publiée en TXT sur `<sélecteur>._domainkey.<domaine>`
  (`v=DKIM1; k=rsa; p=MIIB...`). Le destinataire vérifie la signature (en-tête
  `DKIM-Signature`, champ `s=` = sélecteur).
- Prouve l'**intégrité** et que le message vient d'un serveur détenant la clé du domaine.
- **Limite de l'outil** : le sélecteur est libre (`google`, `selector1`, `s2048`,
  `mailjet`…) et le DNS ne permet pas de lister les sous-domaines. On teste 5 sélecteurs
  courants ; « non trouvé » est donc un **info**, jamais un échec (sinon faux positif).

### DMARC (RFC 7489)
- TXT sur `_dmarc.<domaine>` : `v=DMARC1; p=reject; rua=mailto:dmarc@domaine`.
- Ajoute ce qui manque à SPF/DKIM : **l'alignement** avec le `From:` visible par
  l'utilisateur, et une **politique** quand les deux échouent : `none` (observer
  seulement), `quarantine` (spam), `reject` (refus).
- `rua` = rapports agrégés : on voit qui envoie au nom du domaine. Démarche saine :
  `p=none` → analyse des rapports → `quarantine` → `reject`.
- C'est pour cela que l'outil classe `p=none` en **élevé/warn** : l'alarme est installée
  mais pas armée.

### MX
- Indique si le domaine reçoit des emails. Un domaine **sans** MX doit quand même publier
  `v=spf1 -all` et `p=reject`, sinon il est un candidat idéal à l'usurpation.

**Implémentation** : `dnspython` (`dns.resolver.resolve`) si installé, sinon `nslookup`
parsé par regex (`utils._parse_nslookup_txt`). Les enregistrements TXT longs sont découpés
en segments de 255 caractères, que l'on **concatène**.

## 4. Fuites publiques (`modules/breach.py`)

- Endpoint **gratuit et sans clé** : `GET https://haveibeenpwned.com/api/v3/breaches`
  renvoie le catalogue de toutes les fuites connues (nom, `Domain`, date, nombre de
  comptes, types de données).
- L'outil cherche le domaine audité (ou un sous-/sur-domaine) dans le champ `Domain`.
  Comparaison sur le **domaine complet**, pas sur le label, sinon `adobe.net` matcherait
  `adobe.com` (test unitaire dédié).
- Ce que ça **ne** dit **pas** : si les adresses `@votre-pme.ma` des employés sont dans la
  fuite LinkedIn ou Canva. Ça nécessite l'endpoint `breachedaccount`, payant, volontairement
  non appelé.
- Risque concret visé : **credential stuffing**, c'est-à-dire la réutilisation de mots de
  passe fuités sur d'autres services. Parade : MFA + gestionnaire de mots de passe.

## 5. Correspondance CVE (`modules/cve.py`)

### Étapes
1. **Détection** des versions divulguées par regex : `Server: Apache/2.4.41`,
   `X-Powered-By: PHP/8.3.33`, `<meta name="generator" content="WordPress 6.8.10">`.
2. **Interrogation NVD 2.0** (API publique du NIST, sans clé) :
   - produit connu (`CPE_MAP`) → **correspondance précise par CPE** :
     `virtualMatchString=cpe:2.3:a:php:php:8.3.33:*:*:*:*:*:*:*`. NVD ne renvoie que les
     CVE dont la **plage de versions affectées** contient cette version ;
   - produit inconnu → **recherche par mot-clé** (`keywordSearch=elementor 4.1.4`),
     approximative : la gravité est **plafonnée à « moyen »** et le titre porte
     « A VERIFIER ».
3. **Gravité** = CVSS de la pire CVE (v3.1, puis v3.0, puis v2) : ≥ 9 critique, ≥ 7 élevé,
   ≥ 4 moyen, sinon faible.
4. **Rate-limit** : NVD sans clé ≈ 5 requêtes / 30 s → pause de 6,5 s entre appels, un
   nouvel essai après un HTTP 429, et au plus 4 produits interrogés.

### CPE en deux mots
*Common Platform Enumeration* : identifiant normalisé d'un logiciel,
`cpe:2.3:<type>:<éditeur>:<produit>:<version>:...` (type `a` = application). Les fiches
CVE de NVD listent les CPE vulnérables (avec des bornes de version), ce qui permet un
appariement précis.

### Faux positifs et faux négatifs (à savoir expliquer)
- **Backports** : Debian/Ubuntu/RHEL corrigent une faille **sans changer** le numéro de
  version amont. `Apache/2.4.41 (Ubuntu)` peut être entièrement patché → **faux positif**.
- **Mot-clé** : « php 8.3 » peut remonter une CVE d'un plugin PHP sans rapport → faux
  positif (d'où le plafonnement).
- **Version masquée ou fausse** : aucune version → aucun signal (faux négatif) ; un
  en-tête peut aussi être modifié volontairement.
- **CDN / reverse proxy** : l'en-tête `Server` décrit souvent le proxy (`cloudflare`,
  `hcdn`), pas le serveur d'origine.
- **Composant ≠ exposition** : une CVE dans un module non activé n'est pas exploitable.
- **Conclusion** : une correspondance CVE est un **indice à vérifier**, pas une
  vulnérabilité prouvée. La recommandation est toujours la même : mettre à jour **et**
  masquer la version.

## 6. Le score

Départ 100, chaque `fail` retire le poids de sa gravité (40/25/12/5), chaque `warn` la
moitié (arrondi bancaire de Python : `round(12.5) == 12`). `pass` et `info` ne retirent
rien. Notes : A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, E ≥ 20, F sinon.
Choix de conception : **ce qui est incertain est en `info`**, pour ne pas pénaliser le
client à cause d'une limite de l'outil.

---

## 7. Questions d'entretien (avec réponses modèles)

**1. Qu'entends-tu par audit « passif » ? Où est la limite avec un test d'intrusion ?**
> Je ne lis que ce qui est public et je me comporte comme un visiteur normal : une page
> chargée, une poignée de main TLS, des requêtes DNS, deux bases publiques. Je n'envoie
> aucun payload, aucun brute-force, aucun scan de ports. Un pentest cherche à exploiter,
> et il exige un contrat et un périmètre signés. Même en passif, je n'audite qu'avec
> l'autorisation du propriétaire.

**2. Quelle est la différence entre SPF, DKIM et DMARC ?**
> SPF liste les IP autorisées à envoyer (il vérifie l'enveloppe). DKIM signe le message
> avec une clé dont la partie publique est dans le DNS (intégrité et origine). DMARC
> exige que l'un des deux soit aligné avec le `From:` visible et définit la politique en
> cas d'échec (none, quarantine, reject), avec des rapports.

**3. Pourquoi `p=none` est-il signalé comme un risque élevé ?**
> Parce qu'un email usurpé est quand même livré : DMARC observe sans protéger. C'est une
> étape de transition normale, mais elle doit mener à `quarantine` puis `reject`.

**4. Pourquoi ne pas mettre « DKIM absent » en échec ?**
> On ne peut pas énumérer les sélecteurs DKIM via le DNS. Ne pas en trouver sur 5
> sélecteurs courants ne prouve rien. Le classer en échec produirait des faux positifs,
> donc je le classe en info.

**5. Qu'est-ce que HSTS et contre quelle attaque protège-t-il ?**
> C'est un en-tête qui oblige le navigateur à n'utiliser que HTTPS pour le domaine
> pendant `max-age`. Il protège contre le SSL stripping, où un attaquant en position
> d'homme du milieu rétrograde la connexion en HTTP. La liste de preload protège même
> la toute première visite.

**6. CSP et X-Frame-Options : quelle différence ?**
> CSP contrôle d'où peuvent venir les ressources (scripts, styles…) et limite l'impact
> d'un XSS. X-Frame-Options empêche que la page soit affichée dans une iframe
> (clickjacking). La directive CSP `frame-ancestors` remplace aujourd'hui
> X-Frame-Options.

**7. Comment valides-tu un certificat ? Pourquoi as-tu ajouté certifi ?**
> Je vérifie la chaîne jusqu'à une racine de confiance, la date d'expiration, le nom
> (CN/SAN, avec les règles des wildcards) et la version du protocole. Sur Windows, une
> racine expirée dans le magasin local donnait un faux « certificat expiré ». openssl
> et curl validaient la chaîne. En utilisant le magasin Mozilla (certifi), le résultat
> est le même sur toutes les machines.

**8. Pourquoi TLS 1.0 et 1.1 sont-ils considérés comme non sûrs ?**
> Ils reposent sur des constructions faibles (CBC avec IV prévisible, d'où BEAST,
> MD5/SHA-1 dans le handshake), ne gèrent pas les suites AEAD modernes et ont été
> officiellement dépréciés par la RFC 8996 en 2021. TLS 1.2 est le minimum ; TLS 1.3
> retire les options dangereuses et accélère le handshake.

**9. Comment fonctionne ta correspondance CVE, et pourquoi CPE plutôt que mot-clé ?**
> Je détecte la version, puis j'interroge NVD avec un CPE versionné. NVD ne renvoie que
> les CVE dont la plage de versions affectées contient cette version. La recherche par
> mot-clé renvoie toute CVE qui cite le mot, d'où beaucoup de faux positifs. Quand je
> suis obligé de l'utiliser, je plafonne la gravité et je marque le résultat
> « à vérifier ».

**10. Donne deux sources de faux positifs en CVE matching.**
> Les backports des distributions, qui corrigent la faille sans changer la version
> affichée, et la recherche par mot-clé, qui remonte des CVE sans rapport. Autres
> exemples : un en-tête Server qui décrit le CDN plutôt que l'origine, un module
> vulnérable mais désactivé.

**11. Pourquoi masquer la version d'un serveur si elle est à jour ?**
> C'est de la réduction de surface de reconnaissance (défense en profondeur). Ça ne
> corrige rien, mais ça retire à l'attaquant, ou à un bot, le moyen de cibler
> automatiquement la version le jour où une CVE sort. Ce n'est pas de la sécurité par
> l'obscurité tant que le patching reste la vraie mesure.

**12. Que signifie « domaine présent dans une fuite HIBP » pour une PME ?**
> Des identifiants liés au domaine ont circulé après le piratage d'un service. Le risque
> principal est le credential stuffing. Les parades sont le changement de mot de passe,
> la MFA et l'interdiction de réutiliser les mots de passe. Ce n'est pas forcément le
> site de la PME qui a été piraté.

**13. Comment as-tu rendu l'outil robuste et extensible ?**
> Chaque scanner est un plugin découvert automatiquement dans `modules/` et exécuté de
> façon isolée : s'il plante, l'audit continue. Les helpers réseau ne lèvent jamais
> d'exception. Tous les constats passent par `make_finding`, qui valide le contrat de
> données. Ajouter un contrôle revient à ajouter un fichier.

**14. Comment testes-tu un outil réseau sans réseau ?**
> Avec pytest et monkeypatch : j'injecte de fausses réponses HTTP, DNS, TLS, HIBP et NVD.
> Une fixture `autouse` bloque `socket.create_connection` et `getaddrinfo`, donc un
> appel réseau accidentel fait échouer le test. Les tests sont rapides, déterministes et
> couvrent les cas limites (seuils d'expiration, 429, wildcards, injection HTML dans le
> rapport).

**15. Quelles sont les limites de ton score, et que changerais-tu ?**
> C'est une vue externe ponctuelle qui ne voit ni le réseau interne ni les patchs non
> affichés. Le barème soustractif est sévère et certains points sont comptés deux fois
> (une version exposée est pénalisée dans Headers et dans CVE). Les en-têtes sont jugés
> sur leur présence, pas leur qualité. Je dédoublonnerais, j'évaluerais la qualité de
> HSTS et de la CSP, et j'ajouterais DNSSEC, CAA, MTA-STS et security.txt.
