#!/bin/sh
# Generates the custom name constraints / EKU fixtures under
# tests/fixtures/name_constraints. The certificates are deterministic for a
# given OpenSSL installation and are checked in to the repository, so this
# script only needs to be re-run when the fixture set changes.
set -e

SCRIPT_DIR=${0%/*}
if [ "$SCRIPT_DIR" = "$0" ]; then
    SCRIPT_DIR=.
fi
case "$SCRIPT_DIR" in
    /*) ;;
    *)  SCRIPT_DIR="$PWD/$SCRIPT_DIR" ;;
esac
REPO_ROOT=$(dirname "$SCRIPT_DIR")
# Prefer paths relative to the current working directory: some sandboxed
# environments forbid traversing the absolute path even though the workspace
# itself is writable.
if [ -d "tests/fixtures" ]; then
    OUT_DIR="tests/fixtures/name_constraints"
    CONF="dev/name_constraints_openssl.cnf"
else
    OUT_DIR="$REPO_ROOT/tests/fixtures/name_constraints"
    CONF="$REPO_ROOT/dev/name_constraints_openssl.cnf"
fi
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

mkdir -p "$OUT_DIR"
DAYS=3650

gen_key() {
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
        -out "$WORK_DIR/$1.key.pem" >/dev/null 2>&1
}

self_signed_root() {
    name="$1"
    cn="$2"
    openssl req -new -x509 -key "$WORK_DIR/$name.key.pem" -sha256 \
        -subj "/CN=$cn/O=certvalidator test fixtures/C=US" \
        -set_serial 1 -days "$DAYS" -out "$WORK_DIR/$name.crt.pem" \
        -config "$CONF" -extensions v3_root_ca
}

# issue_ca <name> <issuer_name> <section> <serial>
issue_ca() {
    name="$1"
    issuer="$2"
    section="$3"
    serial="$4"
    openssl req -new -key "$WORK_DIR/$name.key.pem" -sha256 \
        -subj "/CN=$name/O=certvalidator test fixtures/C=US" \
        -out "$WORK_DIR/$name.csr.pem"
    openssl x509 -req -in "$WORK_DIR/$name.csr.pem" \
        -CA "$WORK_DIR/$issuer.crt.pem" -CAkey "$WORK_DIR/$issuer.key.pem" \
        -sha256 -days "$DAYS" -set_serial "$serial" \
        -out "$WORK_DIR/$name.crt.pem" \
        -extfile "$CONF" -extensions "$section"
}

# issue_ee <name> <issuer_name> <section> <serial> <cn>
issue_ee() {
    name="$1"
    issuer="$2"
    section="$3"
    serial="$4"
    cn="$5"
    openssl req -new -key "$WORK_DIR/$name.key.pem" -sha256 \
        -subj "/CN=$cn/O=certvalidator test fixtures/C=US" \
        -out "$WORK_DIR/$name.csr.pem"
    openssl x509 -req -in "$WORK_DIR/$name.csr.pem" \
        -CA "$WORK_DIR/$issuer.crt.pem" -CAkey "$WORK_DIR/$issuer.key.pem" \
        -sha256 -days "$DAYS" -set_serial "$serial" \
        -out "$WORK_DIR/$name.crt.pem" \
        -extfile "$CONF" -extensions "$section"
}

# Root of the custom hierarchy.
gen_key nc_root
self_signed_root nc_root "NC Test Root CA"

# Intermediate constrained to example.com sub-domains (and nothing else).
gen_key nc_dns_ca
issue_ca nc_dns_ca nc_root v3_dns_constrained_ca 100

# Intermediate constrained to an IPv4/IPv6 range.
gen_key nc_ip_ca
issue_ca nc_ip_ca nc_root v3_ip_constrained_ca 200

# Intermediate constrained to an IDNA (punycode A-label) domain.
gen_key nc_idna_ca
issue_ca nc_idna_ca nc_root v3_idna_constrained_ca 250

# Intermediate excluding a specific sub-domain, and one constraining URIs.
gen_key nc_excluded_dns_ca
issue_ca nc_excluded_dns_ca nc_root v3_excluded_dns_ca 260

gen_key nc_uri_ca
issue_ca nc_uri_ca nc_root v3_uri_constrained_ca 270

# Intermediate whose permitted EKUs do not include server authentication.
gen_key nc_eku_ca
issue_ca nc_eku_ca nc_root v3_eku_constrained_ca 300

# End-entity certs under the DNS-constrained intermediate.
gen_key ee_dns_good
issue_ee ee_dns_good nc_dns_ca v3_ee_san_example 401 "good.example.com"

gen_key ee_dns_evil
issue_ee ee_dns_evil nc_dns_ca v3_ee_san_evil 402 "evil.test"

gen_key ee_cn_good
issue_ee ee_cn_good nc_dns_ca v3_ee_cn_only 403 "cn-only.example.com"

gen_key ee_idna_good
issue_ee ee_idna_good nc_dns_ca v3_ee_san_idna 404 "xn--mnich-kva.example.com"

gen_key ee_idna_ulabel
issue_ee ee_idna_ulabel nc_idna_ca v3_ee_san_idna_ulabel 405 "idna-ulabel.example.com"

gen_key ee_excluded
issue_ee ee_excluded nc_excluded_dns_ca v3_ee_san_excluded 406 "host.forbidden.example.com"

gen_key ee_uri_good
issue_ee ee_uri_good nc_uri_ca v3_ee_san_uri_good 407 "uri-good.example.com"

# End-entity certs under the IP-constrained intermediate.
gen_key ee_ip_good
issue_ee ee_ip_good nc_ip_ca v3_ee_san_ip_good 501 "ip-good.example.com"

gen_key ee_ip_bad
issue_ee ee_ip_bad nc_ip_ca v3_ee_san_ip_bad 502 "ip-bad.example.com"

# End-entity under the EKU-constrained intermediate.
gen_key ee_eku_conflict
issue_ee ee_eku_conflict nc_eku_ca v3_ee_server_auth 601 "eku-conflict.example.com"

for name in \
    nc_root nc_dns_ca nc_ip_ca nc_idna_ca nc_excluded_dns_ca nc_uri_ca nc_eku_ca \
    ee_dns_good ee_dns_evil ee_cn_good ee_idna_good ee_idna_ulabel \
    ee_excluded ee_uri_good ee_ip_good ee_ip_bad ee_eku_conflict
do
    openssl x509 -in "$WORK_DIR/$name.crt.pem" -outform DER \
        -out "$OUT_DIR/$name.crt"
done

echo "Wrote fixtures to $OUT_DIR"
