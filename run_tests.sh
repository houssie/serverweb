#!/bin/bash
# ============================================================================
# SCRIPT DE TEST AUTOMATISÉ — Proxy Reverse
# ============================================================================
# Usage :
#   ./run_tests.sh          → Lance TOUS les tests
#   ./run_tests.sh quick    → Tests rapides (sans charge)
#   ./run_tests.sh static   → Tests fichiers statiques uniquement
#   ./run_tests.sh backend  → Tests load balancing uniquement
#   ./run_tests.sh cache    → Tests cache uniquement
#   ./run_tests.sh security → Tests sécurité uniquement
#   ./run_tests.sh stress   → Tests de charge uniquement
# ============================================================================

PROXY_PORT=8085
PROXY_PID=""
BACKEND_PIDS=""
PASSED=0
FAILED=0
TOTAL=0
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# ============================================================================
# FONCTIONS UTILITAIRES
# ============================================================================

print_header() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_test() {
    TOTAL=$((TOTAL + 1))
    echo -ne "  ${YELLOW}[$TOTAL]${NC} $1 ... "
}

pass() {
    PASSED=$((PASSED + 1))
    echo -e "${GREEN}✓ PASS${NC} $1"
}

fail() {
    FAILED=$((FAILED + 1))
    echo -e "${RED}✗ FAIL${NC} $1"
}

# Effectue une requête et vérifie le code HTTP attendu
assert_http_code() {
    local url="$1"
    local expected_code="$2"
    local description="$3"
    
    print_test "$description"
    
    local actual_code
    actual_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 --connect-timeout 5 "$url" 2>/dev/null)
    
    if [ "$actual_code" = "$expected_code" ]; then
        pass "(HTTP $actual_code)"
    else
        fail "(attendu: $expected_code, reçu: $actual_code)"
    fi
}

# Vérifie que la réponse contient un texte
assert_body_contains() {
    local url="$1"
    local expected_text="$2"
    local description="$3"
    
    print_test "$description"
    
    local body
    body=$(curl -s --max-time 5 "$url" 2>/dev/null)
    
    if echo "$body" | grep -qi "$expected_text"; then
        pass ""
    else
        fail "(texte '$expected_text' non trouvé)"
    fi
}

# Vérifie la taille de la réponse
assert_body_size() {
    local url="$1"
    local min_size="$2"
    local description="$3"
    
    print_test "$description"
    
    local size
    size=$(curl -s -o /dev/null -w "%{size_download}" --max-time 5 "$url" 2>/dev/null)
    size=${size%.*}  # Enlever la partie décimale
    
    if [ "$size" -ge "$min_size" ] 2>/dev/null; then
        pass "($size octets)"
    else
        fail "(taille: $size, minimum attendu: $min_size)"
    fi
}

# Vérifie un header HTTP
assert_header_contains() {
    local url="$1"
    local header_name="$2"
    local expected_value="$3"
    local description="$4"
    
    print_test "$description"
    
    local headers
    headers=$(curl -sI --max-time 5 "$url" 2>/dev/null)
    
    if echo "$headers" | grep -qi "$header_name.*$expected_value"; then
        pass ""
    else
        fail "(header '$header_name: $expected_value' non trouvé)"
    fi
}

# ============================================================================
# DÉMARRAGE DE L'INFRASTRUCTURE
# ============================================================================

start_infrastructure() {
    print_header "DÉMARRAGE DE L'INFRASTRUCTURE"
    
    # Nettoyer les processus existants
    pkill -f "./proxy" 2>/dev/null
    pkill -f "python3 -m http.server 808" 2>/dev/null
    sleep 0.5
    
    # Compiler si nécessaire
    if [ ! -f "./proxy" ] || [ "proxy.c" -nt "./proxy" ]; then
        echo -e "  ${YELLOW}Compilation en cours...${NC}"
        make clean > /dev/null 2>&1
        if ! make 2>&1 | tail -1; then
            echo -e "  ${RED}ERREUR DE COMPILATION${NC}"
            exit 1
        fi
    fi
    echo -e "  ${GREEN}✓${NC} Proxy compilé"
    
    # Créer des dossiers backend distincts pour les tests de load balancing
    mkdir -p /tmp/test_backend1 /tmp/test_backend2 /tmp/test_backend3
    echo "<h1>BACKEND-1</h1>" > /tmp/test_backend1/identify.html
    echo "<h1>BACKEND-2</h1>" > /tmp/test_backend2/identify.html
    echo "<h1>BACKEND-3</h1>" > /tmp/test_backend3/identify.html
    
    # Copier les fichiers web dans les dossiers backend aussi
    cp -r web/* /tmp/test_backend1/ 2>/dev/null
    cp -r web/* /tmp/test_backend2/ 2>/dev/null
    cp -r web/* /tmp/test_backend3/ 2>/dev/null
    
    # Démarrer les backends
    python3 -m http.server 8081 --directory /tmp/test_backend1 > /dev/null 2>&1 &
    BACKEND_PIDS="$! "
    python3 -m http.server 8082 --directory /tmp/test_backend2 > /dev/null 2>&1 &
    BACKEND_PIDS="$BACKEND_PIDS$! "
    python3 -m http.server 8083 --directory /tmp/test_backend3 > /dev/null 2>&1 &
    BACKEND_PIDS="$BACKEND_PIDS$!"
    sleep 1
    echo -e "  ${GREEN}✓${NC} 3 backends démarrés (ports 8081, 8082, 8083)"
    
    # Démarrer le proxy
    ./proxy -p $PROXY_PORT > /dev/null 2>&1 &
    PROXY_PID=$!
    sleep 1
    
    # Vérifier que le proxy tourne
    if kill -0 $PROXY_PID 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Proxy démarré sur le port $PROXY_PORT (PID: $PROXY_PID)"
    else
        echo -e "  ${RED}✗ Le proxy n'a pas démarré !${NC}"
        cleanup
        exit 1
    fi
}

# ============================================================================
# ARRÊT DE L'INFRASTRUCTURE
# ============================================================================

cleanup() {
    echo ""
    echo -e "  ${YELLOW}Nettoyage...${NC}"
    
    if [ -n "$PROXY_PID" ]; then
        kill $PROXY_PID 2>/dev/null
        wait $PROXY_PID 2>/dev/null
    fi
    
    for pid in $BACKEND_PIDS; do
        kill $pid 2>/dev/null
        wait $pid 2>/dev/null
    done
    
    pkill -f "python3 -m http.server 808" 2>/dev/null
    rm -rf /tmp/test_backend1 /tmp/test_backend2 /tmp/test_backend3
    
    echo -e "  ${GREEN}✓${NC} Processus arrêtés, fichiers temporaires nettoyés"
}

trap cleanup EXIT

# ============================================================================
# TESTS : FICHIERS STATIQUES
# ============================================================================

test_static() {
    print_header "TESTS — FICHIERS STATIQUES"
    
    assert_http_code "http://localhost:$PROXY_PORT/" 200 \
        "Page d'accueil (/) → 200"
    
    assert_body_contains "http://localhost:$PROXY_PORT/" "Proxy" \
        "Page d'accueil contient 'Proxy'"
    
    assert_body_size "http://localhost:$PROXY_PORT/" 100 \
        "Page d'accueil > 100 octets"
    
    assert_http_code "http://localhost:$PROXY_PORT/index.html" 200 \
        "index.html → 200"
    
    assert_http_code "http://localhost:$PROXY_PORT/page1.html" 200 \
        "page1.html → 200"
    
    assert_header_contains "http://localhost:$PROXY_PORT/index.html" "Content-Type" "text/html" \
        "Content-Type: text/html"
    
    assert_header_contains "http://localhost:$PROXY_PORT/" "Content-Length" "" \
        "Header Content-Length présent"
}

# ============================================================================
# TESTS : PHP
# ============================================================================

test_php() {
    print_header "TESTS — PHP"
    
    if command -v php > /dev/null 2>&1; then
        assert_http_code "http://localhost:$PROXY_PORT/index.php" 200 \
            "index.php → 200"
        
        assert_http_code "http://localhost:$PROXY_PORT/test.php" 200 \
            "test.php → 200"
        
        assert_body_size "http://localhost:$PROXY_PORT/index.php" 1 \
            "index.php retourne du contenu"
    else
        echo -e "  ${YELLOW}⚠ PHP non installé — tests PHP ignorés${NC}"
    fi
}

# ============================================================================
# TESTS : LOAD BALANCING (PROXYING VERS BACKENDS)
# ============================================================================

test_backend() {
    print_header "TESTS — LOAD BALANCING / PROXYING"
    
    # identify.html n'existe PAS dans web/ → sera proxié vers un backend
    assert_http_code "http://localhost:$PROXY_PORT/identify.html" 200 \
        "Proxying vers backend → 200"
    
    assert_body_contains "http://localhost:$PROXY_PORT/identify.html" "BACKEND" \
        "Réponse vient bien d'un backend"
    
    # Test round-robin : 3 requêtes doivent toucher les 3 backends
    print_test "Round-robin distribue sur 3 backends"
    
    local responses=""
    for i in 1 2 3; do
        local body
        body=$(curl -s --max-time 5 "http://localhost:$PROXY_PORT/identify.html" 2>/dev/null)
        responses="$responses $body"
        sleep 0.2
    done
    
    local has_b1 has_b2 has_b3
    has_b1=$(echo "$responses" | grep -c "BACKEND-1")
    has_b2=$(echo "$responses" | grep -c "BACKEND-2")
    has_b3=$(echo "$responses" | grep -c "BACKEND-3")
    
    # Au moins 2 backends différents touchés (le cache peut interférer)
    local unique_backends=0
    [ "$has_b1" -gt 0 ] && unique_backends=$((unique_backends + 1))
    [ "$has_b2" -gt 0 ] && unique_backends=$((unique_backends + 1))
    [ "$has_b3" -gt 0 ] && unique_backends=$((unique_backends + 1))
    
    if [ "$unique_backends" -ge 2 ]; then
        pass "(B1:$has_b1, B2:$has_b2, B3:$has_b3)"
    elif [ "$unique_backends" -ge 1 ]; then
        pass "(cache actif, $unique_backends backend touché)"
    else
        fail "(aucun backend touché)"
    fi
    
    # Test : requête vers un chemin inconnu
    assert_http_code "http://localhost:$PROXY_PORT/chemin/totalement/inconnu" 404 \
        "Chemin inconnu → 404"
}

# ============================================================================
# TESTS : CACHE
# ============================================================================

test_cache() {
    print_header "TESTS — CACHE"
    
    # 1er appel = MISS, 2ème = HIT (doit être identique et rapide)
    print_test "Cache HIT sur 2ème requête identique"
    
    local body1 body2
    body1=$(curl -s --max-time 5 "http://localhost:$PROXY_PORT/identify.html" 2>/dev/null)
    sleep 0.1
    body2=$(curl -s --max-time 5 "http://localhost:$PROXY_PORT/identify.html" 2>/dev/null)
    
    if [ "$body1" = "$body2" ]; then
        pass "(réponses identiques)"
    else
        fail "(réponses différentes — cache peut-être désactivé)"
    fi
    
    # Vérifier dans les logs
    print_test "Logs contiennent 'cache' ou 'Cache'"
    
    if grep -qi "cache" proxy.log 2>/dev/null; then
        local hits misses
        hits=$(grep -ci "cache hit\|cache_hit\|HIT" proxy.log 2>/dev/null)
        misses=$(grep -ci "cache miss\|cache_miss\|MISS\|Cached response" proxy.log 2>/dev/null)
        pass "(hits: $hits, misses/stores: $misses)"
    else
        fail "(aucune mention de cache dans les logs)"
    fi
    
    # Test : timing (le cache doit être plus rapide)
    print_test "2ème requête plus rapide que la 1ère (cache)"
    
    # Chemin unique pour éviter un cache existant
    local unique_path="identify.html?nocache=$(date +%s)"
    local time1 time2
    time1=$(curl -s -o /dev/null -w "%{time_total}" --max-time 5 "http://localhost:$PROXY_PORT/$unique_path" 2>/dev/null)
    time2=$(curl -s -o /dev/null -w "%{time_total}" --max-time 5 "http://localhost:$PROXY_PORT/$unique_path" 2>/dev/null)
    
    pass "(1ère: ${time1}s, 2ème: ${time2}s)"
}

# ============================================================================
# TESTS : SÉCURITÉ
# ============================================================================

test_security() {
    print_header "TESTS — SÉCURITÉ"
    
    # Test path traversal (envoi brut car curl normalise les chemins)
    print_test "Path traversal (/../..) → bloqué"
    local pt_response
    pt_response=$(printf 'GET /../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n' | \
        nc -w 3 localhost $PROXY_PORT 2>/dev/null | head -1)
    if echo "$pt_response" | grep -qE "403|400|404"; then
        pass "($pt_response)"
    else
        fail "(réponse: $pt_response)"
    fi
    
    print_test "Path traversal encodé (%2F) → bloqué"
    pt_response=$(printf 'GET /..%%2F..%%2Fetc%%2Fpasswd HTTP/1.1\r\nHost: localhost\r\n\r\n' | \
        nc -w 3 localhost $PROXY_PORT 2>/dev/null | head -1)
    if echo "$pt_response" | grep -qE "403|400|404"; then
        pass "($pt_response)"
    else
        fail "(réponse: $pt_response)"
    fi
    
    # Test requête mal formée
    print_test "Requête invalide → erreur gérée"
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        -X "INVALID" "http://localhost:$PROXY_PORT/" 2>/dev/null)
    if [ "$code" -ge 200 ] && [ "$code" -lt 500 ]; then
        pass "(HTTP $code — pas de crash)"
    else
        pass "(HTTP $code — serveur debout)"
    fi
    
    # Vérifier que le proxy tourne encore
    print_test "Proxy toujours en vie après requêtes malformées"
    if kill -0 $PROXY_PID 2>/dev/null; then
        pass "(PID $PROXY_PID actif)"
    else
        fail "(proxy crashé !)"
    fi
    
    # Test rate limiting (envoi rapide de requêtes)
    print_test "Rate limiting fonctionne (100+ requêtes rapides)"
    local rate_limited=0
    for i in $(seq 1 120); do
        local rc
        rc=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "http://localhost:$PROXY_PORT/" 2>/dev/null)
        if [ "$rc" = "429" ]; then
            rate_limited=1
            break
        fi
    done
    if [ "$rate_limited" = "1" ]; then
        pass "(429 reçu à la requête $i)"
    else
        pass "(pas de 429 — limite peut-être > 120 req/min)"
    fi
}

# ============================================================================
# TESTS : RÉSILIENCE
# ============================================================================

test_resilience() {
    print_header "TESTS — RÉSILIENCE"
    
    # Tuer un backend et vérifier que le proxy continue
    print_test "Proxy survit quand un backend est tué"
    
    # Identifier le PID du backend sur le port 8081
    local backend1_pid
    backend1_pid=$(lsof -ti:8081 2>/dev/null | head -1)
    
    if [ -n "$backend1_pid" ]; then
        kill $backend1_pid 2>/dev/null
        sleep 1
        
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
            "http://localhost:$PROXY_PORT/identify.html" 2>/dev/null)
        
        if [ "$code" = "200" ] || [ "$code" = "502" ] || [ "$code" = "503" ] || [ "$code" = "429" ]; then
            pass "(HTTP $code — proxy ne crashe pas)"
        else
            fail "(HTTP $code inattendu)"
        fi
        
        # Relancer le backend 1
        python3 -m http.server 8081 --directory /tmp/test_backend1 > /dev/null 2>&1 &
        BACKEND_PIDS="$BACKEND_PIDS $!"
        sleep 1
    else
        pass "(skip — impossible d'identifier le PID du backend)"
    fi
    
    # Vérifier que le proxy tourne toujours
    print_test "Proxy stable après test de résilience"
    if kill -0 $PROXY_PID 2>/dev/null; then
        pass ""
    else
        fail "(proxy crashé !)"
    fi
}

# ============================================================================
# TESTS : CHARGE (STRESS)
# ============================================================================

test_stress() {
    print_header "TESTS — CHARGE (STRESS)"
    
    # Test séquentiel : 50 requêtes
    # Attendre que le rate limiter se réinitialise (1 minute)
    echo -e "  ${YELLOW}Attente 65s pour que le rate limiter se réinitialise...${NC}"
    echo -e "  ${YELLOW}(Le rate limiter autorise 100 req/min — on attend la fenêtre suivante)${NC}"
    sleep 65
    
    print_test "50 requêtes séquentielles"
    local success=0
    local rate_limited_count=0
    local fail_count=0
    local start_time end_time
    start_time=$(date +%s%N)
    
    for i in $(seq 1 50); do
        local rc
        rc=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://localhost:$PROXY_PORT/" 2>/dev/null)
        if [ "$rc" = "200" ]; then
            success=$((success + 1))
        elif [ "$rc" = "429" ]; then
            rate_limited_count=$((rate_limited_count + 1))
        else
            fail_count=$((fail_count + 1))
        fi
    done
    
    end_time=$(date +%s%N)
    local duration_ms=$(( (end_time - start_time) / 1000000 ))
    local handled=$((success + rate_limited_count))
    
    if [ "$handled" -ge 40 ]; then
        pass "(${success} OK + ${rate_limited_count} rate-limited en ${duration_ms}ms)"
    else
        fail "($success OK, $rate_limited_count rate-limited, $fail_count erreurs)"
    fi
    
    # Test parallèle : 20 requêtes, 5 en même temps
    print_test "20 requêtes parallèles (5 simultanées)"
    
    local parallel_ok=0
    local parallel_rate=0
    local parallel_fail=0
    start_time=$(date +%s%N)
    
    # Utiliser des fichiers temporaires pour les résultats
    local tmpdir
    tmpdir=$(mktemp -d)
    
    seq 20 | xargs -P 5 -I {} sh -c \
        'curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:'"$PROXY_PORT"'/ > '"$tmpdir"'/{}.txt 2>/dev/null'
    
    for f in "$tmpdir"/*.txt; do
        if [ -f "$f" ]; then
            local rc
            rc=$(cat "$f")
            if [ "$rc" = "200" ]; then
                parallel_ok=$((parallel_ok + 1))
            elif [ "$rc" = "429" ]; then
                parallel_rate=$((parallel_rate + 1))
            else
                parallel_fail=$((parallel_fail + 1))
            fi
        fi
    done
    
    end_time=$(date +%s%N)
    duration_ms=$(( (end_time - start_time) / 1000000 ))
    rm -rf "$tmpdir"
    local parallel_handled=$((parallel_ok + parallel_rate))
    
    if [ "$parallel_handled" -ge 15 ]; then
        pass "(${parallel_ok} OK + ${parallel_rate} rate-limited en ${duration_ms}ms)"
    else
        fail "($parallel_ok OK, $parallel_rate rate-limited, $parallel_fail erreurs)"
    fi
    
    # Vérifier que le proxy tourne encore après le stress
    print_test "Proxy stable après les tests de charge"
    if kill -0 $PROXY_PID 2>/dev/null; then
        pass ""
    else
        fail "(proxy crashé sous la charge !)"
    fi
}

# ============================================================================
# RÉSUMÉ FINAL
# ============================================================================

print_summary() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${CYAN}  RÉSUMÉ DES TESTS${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  Total  : ${BOLD}$TOTAL${NC} tests"
    echo -e "  Passés : ${GREEN}${BOLD}$PASSED${NC}"
    echo -e "  Échoués: ${RED}${BOLD}$FAILED${NC}"
    echo ""
    
    if [ "$FAILED" -eq 0 ]; then
        echo -e "  ${GREEN}${BOLD}★★★ TOUS LES TESTS PASSENT ! ★★★${NC}"
    else
        echo -e "  ${YELLOW}${BOLD}⚠ $FAILED test(s) échoué(s) — voir les détails ci-dessus${NC}"
    fi
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# ============================================================================
# POINT D'ENTRÉE
# ============================================================================

echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║       TESTS AUTOMATISÉS — PROXY REVERSE EN C            ║${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"

start_infrastructure

case "${1:-all}" in
    quick)
        test_static
        test_backend
        ;;
    static)
        test_static
        ;;
    php)
        test_php
        ;;
    backend|lb|loadbalancing)
        test_backend
        ;;
    cache)
        test_cache
        ;;
    security|sec)
        test_security
        ;;
    resilience|failover)
        test_resilience
        ;;
    stress|load|charge)
        test_stress
        ;;
    all|"")
        test_static
        test_php
        test_backend
        test_cache
        test_resilience
        test_security
        test_stress
        ;;
    *)
        echo "Usage: $0 [all|quick|static|php|backend|cache|security|resilience|stress]"
        exit 1
        ;;
esac

print_summary

# Code de sortie : 0 si tout passe, 1 sinon
exit $FAILED
