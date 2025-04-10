#!/bin/bash
# deploy_ca.sh : Script d’automatisation pour déployer une hiérarchie d’AC (Partie 2 du TP)
#
# Ce script réalise les opérations suivantes :
#  1. Création de l’environnement (répertoires et fichiers de base)
#  2. Génération de la clé privée et du certificat auto-signé de l’AC racine (valable 15 ans)
#  3. Génération de la clé et de la requête de certificat (CSR) pour l’AC subordonnée
#  4. Signature du certificat de l’AC subordonnée par l’AC racine (valable 10 ans)
#  5. Création d’une CRL pour l’AC racine
#
# Les paramètres de sujet sont définis comme suit :
#   Country Name (C)             = FR
#   State or Province Name (ST)   = Île-de-France
#   Locality Name (L)             = Paris
#   Organization Name (O)         = td1-sup-de-vinci
#   Common Name (CN)              = AB_FM.sup-de-vinci.local
#
# Utilisation :
#   ./deploy_ca.sh init         -> Crée l’environnement (si ce n’est déjà fait)
#   ./deploy_ca.sh create-root  -> Génère la clé et le certificat de l’AC racine
#   ./deploy_ca.sh create-sub   -> Génère la clé, le CSR et signe le certificat de l’AC subordonnée
#   ./deploy_ca.sh gen-crl      -> Génère la CRL pour l’AC racine
#   ./deploy_ca.sh help         -> Affiche ce message d’aide
#
# Ce script doit être exécuté avec des droits suffisants pour écrire dans l’arborescence.
# Vous pouvez l’adapter selon vos besoins (par exemple, pour intégrer SoftHSM).
set -e  # Arrêter le script dès qu'une commande échoue

# ---------------
# Paramètres globaux
# ---------------
COUNTRY="FR"
STATE="Île-de-France"
LOCALITY="Paris"
ORGANIZATION="td1-sup-de-vinci"
COMMON_NAME="AB_FM.sup-de-vinci.local"

# Validités en jours
VALIDITY_ROOT=5475      # 15 ans (15*365)
VALIDITY_SUB=3650       # 10 ans (10*365)
VALIDITY_FINAL=365      # 1 an

# Chemins de travail
WORKDIR="$(pwd)/pki_env"
ROOT_DIR="$WORKDIR/rootCA"
SUB_DIR="$WORKDIR/subCA"

# Nom des fichiers de configuration
ROOT_OPENSSL_CONF="$ROOT_DIR/openssl.cnf"
SUB_OPENSSL_CONF="$SUB_DIR/openssl.cnf"

OCSP_HTTP_URL="http://ocsp.sup-de-vinci.local"
CRL_DP_URL="http://crl.sup-de-vinci.local/root.crl.pem"
SMIME_EMAIL="user@sup-de-vinci.local"
# ---------------
# Fonctions utilitaires
# ---------------
function print_help() {
    echo "Usage: $0 {init|create-root|create-sub|gen-crl|create-final|setup-ocsp|check-ocsp|create-smime|cross-sign|help}"
    echo "  init         : Crée l'environnement de travail"
    echo "  create-root  : Génère la clé et le certificat auto-signé de l’AC racine"
    echo "  create-sub   : Génère la clé, la requête de certificat et signe l’AC subordonnée avec l’AC racine"
    echo "  gen-crl      : Génère une CRL pour l’AC racine"
    echo "  create-final <nom> : Génère un certificat final (valable 1 an)"
    echo "  setup-ocsp   : Configure le répondeur OCSP"
    echo "  check-ocsp <cert> : Vérifie un certificat via OCSP"
    echo "  create-smime <email> : Génère un certificat S/MIME"
    echo "  cross-sign   : Implémente la certification croisée"
    echo "  help         : Affiche ce message"
}

# Fonction pour créer l’arborescence et les fichiers de base pour une AC
function init_ca_env() {
    echo "Création de l’environnement PKI dans $WORKDIR ..."
    mkdir -p "$ROOT_DIR"/{certs,crl,newcerts,private}
    mkdir -p "$SUB_DIR"/{certs,crl,newcerts,private}
    # Les fichiers de bases requis par OpenSSL
    touch "$ROOT_DIR/index.txt"
    echo "01" > "$ROOT_DIR/serial"
    touch "$SUB_DIR/index.txt"
    echo "01" > "$SUB_DIR/serial"

    echo "Création des fichiers de configuration OpenSSL pour Root CA et Sub CA ..."
    # Fichier de configuration pour l’AC racine
    cat > "$ROOT_OPENSSL_CONF" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $ROOT_DIR
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
RANDFILE          = \$dir/private/.rand
private_key       = \$dir/private/root.key.pem
certificate       = \$dir/certs/root.cert.pem
default_md        = sha256
default_crl_days  = 30
policy            = policy_strict
x509_extensions   = v3_ca

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
commonName              = supplied

[ req ]
default_bits        = 4096
distinguished_name  = req_distinguished_name
string_mask         = utf8only

[ req_distinguished_name ]
countryName_default             = $COUNTRY
stateOrProvinceName_default     = $STATE
localityName_default            = $LOCALITY
organizationName_default        = $ORGANIZATION
commonName_default              = $COMMON_NAME
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
organizationName                = Organization Name
commonName                      = Common Name

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:2
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

# Extension pour signer une AC subordonnée
[v3_intermediate]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
EOF

    # Fichier de configuration pour l’AC subordonnée
    cat > "$SUB_OPENSSL_CONF" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $SUB_DIR
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
RANDFILE          = \$dir/private/.rand
private_key       = \$dir/private/sub.key.pem
certificate       = \$dir/certs/sub.cert.pem
default_md        = sha256
policy            = policy_loose
x509_extensions   = usr_cert

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
commonName              = supplied

[ req ]
default_bits        = 4096
distinguished_name  = req_distinguished_name
string_mask         = utf8only

[ req_distinguished_name ]
countryName_default             = $COUNTRY
stateOrProvinceName_default     = $STATE
localityName_default            = $LOCALITY
organizationName_default        = $ORGANIZATION
commonName_default              = $COMMON_NAME
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
organizationName                = Organization Name
commonName                      = Common Name

[ usr_cert ]
basicConstraints = critical, CA:false
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash

[ ocsp_ext ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = critical, OCSPSigning

[ smime_ext ]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = emailProtection
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

[ v3_cross ]
basicConstraints = critical,CA:true,pathlen:0
keyUsage = keyCertSign,cRLSign
authorityInfoAccess = "OCSP;URI:$OCSP_HTTP_URL"
EOF

    echo "Environnement créé avec succès."
}

# ---------------
# Création de l’AC racine
# ---------------
function create_root() {
    echo "Création de la clé privée de l’AC racine ..."
    openssl genrsa -out "$ROOT_DIR/private/root.key.pem" 4096
    chmod 400 "$ROOT_DIR/private/root.key.pem"
    
    echo "Création de la demande de certificat (CSR) pour l’AC racine ..."
    openssl req -config "$ROOT_OPENSSL_CONF" \
          -key "$ROOT_DIR/private/root.key.pem" \
          -new -x509 -days $VALIDITY_ROOT -sha256 \
          -extensions v3_ca \
          -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/CN=$COMMON_NAME" \
          -out "$ROOT_DIR/certs/root.cert.pem"
    
    echo "Certificat racine créé : $ROOT_DIR/certs/root.cert.pem"
}

# ---------------
# Création de l’AC subordonnée
# ---------------
function create_sub() {
    echo "Création de la clé privée de l’AC subordonnée..."
    openssl genrsa -out "$SUB_DIR/private/sub.key.pem" 4096
    chmod 400 "$SUB_DIR/private/sub.key.pem"
    
    echo "Création de la demande de certificat (CSR) pour l’AC subordonnée..."
    openssl req -config "$SUB_OPENSSL_CONF" \
          -new -key "$SUB_DIR/private/sub.key.pem" \
          -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/CN=$COMMON_NAME" \
          -out "$SUB_DIR/csr_sub.csr.pem"
    
    echo "Signature de la demande de l’AC subordonnée par l’AC racine..."
    # Utilisation de l'extension [v3_intermediate] définie dans ROOT_OPENSSL_CONF
    openssl ca -config "$ROOT_OPENSSL_CONF" -batch \
          -extensions v3_intermediate -days $VALIDITY_SUB -notext -md sha256 \
          -in "$SUB_DIR/csr_sub.csr.pem" \
          -out "$SUB_DIR/certs/sub.cert.pem"
    
    echo "Certificat de l’AC subordonnée signé et enregistré dans : $SUB_DIR/certs/sub.cert.pem"
}

# ---------------
# Génération d’une CRL pour l’AC racine
# ---------------
function generate_crl() {
    echo "Génération de la CRL pour l’AC racine..."
    openssl ca -config "$ROOT_OPENSSL_CONF" -gencrl -out "$ROOT_DIR/crl/root.crl.pem"
    echo "CRL générée et enregistrée dans : $ROOT_DIR/crl/root.crl.pem"
}

# ---------------
# Main (traitement de la commande)
# ---------------
if [[ $# -lt 1 ]]; then
    print_help
    exit 1
fi

# Génération d'un certificat final
function create_final() {
    local ENTITY_NAME="$1"
    echo "Création du certificat final $ENTITY_NAME..."
    
    mkdir -p "$SUB_DIR/final-certs"
    
    # Génération clé
    openssl genrsa -out "$SUB_DIR/final-certs/$ENTITY_NAME.key.pem" 2048
    chmod 400 "$SUB_DIR/final-certs/$ENTITY_NAME.key.pem"
    
    # CSR
    openssl req -new -key "$SUB_DIR/final-certs/$ENTITY_NAME.key.pem" \
        -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/CN=$ENTITY_NAME" \
        -out "$SUB_DIR/final-certs/$ENTITY_NAME.csr.pem"
    
    # Signature avec extensions adaptées
    openssl ca -config "$SUB_OPENSSL_CONF" -batch \
        -days $VALIDITY_FINAL -notext -md sha256 \
        -in "$SUB_DIR/final-certs/$ENTITY_NAME.csr.pem" \
        -out "$SUB_DIR/final-certs/$ENTITY_NAME.cert.pem" \
        -extensions usr_cert
    
    echo "Certificat final généré : $SUB_DIR/final-certs/$ENTITY_NAME.cert.pem"
}

# Configuration OCSP
function setup_ocsp() {
    echo "Configuration du répondeur OCSP..."
    
    # Génération certificat OCSP
    openssl ca -config "$SUB_OPENSSL_CONF" -batch \
        -extensions ocsp_ext \
        -days $VALIDITY_FINAL \
        -in <(openssl req -new -key "$SUB_DIR/private/sub.key.pem" \
            -subj "/CN=OCSP-Responder") \
        -out "$SUB_DIR/certs/ocsp.cert.pem"

    # Mise à jour configuration avec extensions
    sed -i '/\[ usr_cert \]/a authorityInfoAccess = OCSP;URI:'$OCSP_HTTP_URL'\ncrlDistributionPoints = URI:'$CRL_DP_URL $SUB_OPENSSL_CONF
}

# Vérification OCSP
function check_ocsp() {
    local CERT="$1"
    echo "Vérification OCSP pour $CERT..."
    
    openssl ocsp -issuer "$SUB_DIR/certs/sub.cert.pem" \
        -CAfile "$ROOT_DIR/certs/root.cert.pem" \
        -cert "$CERT" \
        -url "$OCSP_HTTP_URL" \
        -resp_text
}

# Gestion S/MIME
function create_smime() {
    local USER="$1"
    echo "Création certificat S/MIME pour $USER..."
    
    # Génération avec extensions spécifiques
    openssl req -newkey rsa:2048 -nodes -keyout "$SUB_DIR/final-certs/$USER.key.pem" \
        -subj "/emailAddress=$USER/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/CN=$USER" \
        -out "$SUB_DIR/final-certs/$USER.csr.pem"
    
    openssl ca -config "$SUB_OPENSSL_CONF" -batch \
        -extensions smime_ext \
        -days $VALIDITY_FINAL \
        -in "$SUB_DIR/final-certs/$USER.csr.pem" \
        -out "$SUB_DIR/final-certs/$USER.cert.pem"

    # Conversion au format PKCS#12
    openssl pkcs12 -export \
        -inkey "$SUB_DIR/final-certs/$USER.key.pem" \
        -in "$SUB_DIR/final-certs/$USER.cert.pem" \
        -out "$SUB_DIR/final-certs/$USER.p12"
}

# Certification croisée
function cross_sign() {
    echo "Création de la certification croisée..."
    
    # Génération CSR depuis l'autre AC
    openssl req -new -key "$SUB_DIR/private/sub.key.pem" \
        -subj "/C=$COUNTRY/ST=$STATE/L=$LOCALITY/O=$ORGANIZATION/CN=Cross-Signed" \
        -out "$SUB_DIR/csr_cross.csr.pem"
    
    # Signature avec contraintes
    openssl ca -config "$ROOT_OPENSSL_CONF" -batch \
        -extensions v3_cross \
        -days $VALIDITY_SUB \
        -in "$SUB_DIR/csr_cross.csr.pem" \
        -out "$SUB_DIR/certs/cross.cert.pem"
}

case "$1" in
    init)
        init_ca_env
        ;;
    create-root)
        create_root
        ;;
    create-sub)
        create_sub
        ;;
    gen-crl)
        generate_crl
        ;;
    create-final)
        if [[ -z "$2" ]]; then
            echo "Erreur: Spécifiez un nom pour le certificat final."
            exit 1
        fi
        create_final "$2"
        ;;
    setup-ocsp)
        setup_ocsp
        ;;
    check-ocsp)
        if [[ -z "$2" ]]; then
            echo "Erreur: Spécifiez un certificat à vérifier."
            exit 1
        fi
        check_ocsp "$2"
        ;;
    create-smime)
        if [[ -z "$2" ]]; then
            echo "Erreur: Spécifiez une adresse email."
            exit 1
        fi
        create_smime "$2"
        ;;
    cross-sign)
        cross_sign
        ;;
    help|*)
        print_help
        ;;
esac