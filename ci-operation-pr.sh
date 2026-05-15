#!/bin/bash
#
# free5GC PR Test Script
#
# Note: Please do not run this script with sudo! 
#       The script will automatically use sudo when needed.
#
# Usage:
#   ./ci-operation-pr.sh nf <NF1> <PR1> [<PR2> ...] [<NF2> <PR3> ...] [OPTIONS]
#   ./ci-operation-pr.sh nf <NF1> <PR1> [...] lib <LIB1> <PR1> [...] [OPTIONS]
#   ./ci-operation-pr.sh lib <LIBRARY> <PR#> [OPTIONS]
#   ./ci-operation-pr.sh free5gc <PR#> nf <NF1> <PR1> [<NF2> <PR2> ...] [OPTIONS]
#
# OPTIONS:
#   --skip-docker    Skip Docker Compose tests
#   --skip-testall   Skip go test tests
#   --skip-pull      Skip pulling (if already pulled)
#
# Examples:
#   ./ci-operation-pr.sh nf amf 193
#   ./ci-operation-pr.sh nf smf 170 183 192
#   ./ci-operation-pr.sh nf smf 170 183 192 udm 80 81 amf 50
#   ./ci-operation-pr.sh nf smf 188 udm 77 --skip-docker
#   ./ci-operation-pr.sh nf udm 76 lib util 37         # NF PR + library PR
#   ./ci-operation-pr.sh nf amf 50 smf 60 lib nas 44 openapi 67  # Multiple
#   ./ci-operation-pr.sh lib openapi 67
#   ./ci-operation-pr.sh free5gc 787 nf amf 194   # Test main repo PR with NF PR
#

set -e

# Check if running as root (not recommended)
if [ "$EUID" -eq 0 ]; then
    echo "Warning: Please do not run this script with sudo!"
    echo "Correct usage: ./ci-test-pr.sh nf amf 193"
    echo "The script will automatically use sudo when needed."
    exit 1
fi

# Setup Go environment
export GOPATH=$HOME/go
if [ -d "/usr/local/go" ]; then
    export GOROOT=/usr/local/go
elif [ -d "/usr/lib/golang" ]; then
    export GOROOT=/usr/lib/golang
fi
export PATH=$PATH:$GOPATH/bin:$GOROOT/bin

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Config
TEST_POOL="TestRegistration TestGUTIRegistration TestServiceRequest TestXnHandover TestN2Handover TestDeregistration TestPDUSessionReleaseRequest TestPaging TestReSynchronization TestDuplicateRegistration TestEAPAKAPrimeAuthentication TestMultiAmfRegistration TestNasReroute TestDC TestDynamicDC TestXnDCHandover TestNon3GPP"
TNGF_TIMEOUT=300
TEST_TIMEOUT=300
DOCKER_TIMEOUT=300

# Supported libraries and NFs
SUPPORTED_LIBS="openapi util nas ngap pfcp aper"
SUPPORTED_NFS="amf ausf bsf chf n3iwf nef nrf nssf pcf smf tngf udm udr upf webconsole"

# Report directory
REPORT_DIR="testing_output"

is_lib() {
    local name=$1
    [[ " $SUPPORTED_LIBS " =~ " $name " ]]
}

usage() {
    echo "Usage:"
    echo "  $0 nf <NF1> <PR1> [<PR2> ...] [<NF2> <PR3> ...] [OPTIONS]"
    echo "  $0 nf <NF1> <PR1> [...] lib <LIB1> <PR1> [...] [OPTIONS]"
    echo "  $0 lib <LIBRARY> <PR#> [OPTIONS]"
    echo "  $0 free5gc <PR#> nf <NF1> <PR1> [<NF2> <PR2> ...] [OPTIONS]"
    echo ""
    echo "OPTIONS:"
    echo "  --skip-docker    Skip Docker Compose tests"
    echo "  --skip-testall   Skip go test tests"
    echo "  --skip-pull      Skip pulling (if already done)"
    echo ""
    echo "Examples:"
    echo "  $0 nf amf 193"
    echo "  $0 nf smf 170 183 192              # Multiple PRs for same NF"
    echo "  $0 nf smf 170 183 udm 80 81 amf 50 # Multiple NFs with multiple PRs"
    echo "  $0 nf udm 76 lib util 37           # NF PR + library PR combined"
    echo "  $0 lib openapi 67"
    echo "  $0 free5gc 787 nf amf 194          # Test main repo PR #787 with AMF PR #194"
    echo ""
    echo "Supported NFs: $SUPPORTED_NFS"
    echo "Supported Libraries: $SUPPORTED_LIBS"
    exit 1
}

log_step() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${YELLOW}[$1/6] $2${NC}"
    echo -e "${BLUE}========================================${NC}"
}

log_info() {
    echo -e "${GREEN}[INFO] $1${NC}"
}

log_warn() {
    echo -e "${RED}[WARN] $1${NC}"
}

log_pass() {
    echo -e "${GREEN}[PASS] $1${NC}"
}

log_fail() {
    echo -e "${RED}[FAIL] $1${NC}"
}

SUDO_KEEPALIVE_PID=""

cleanup_sudo_keepalive() {
    if [ -n "$SUDO_KEEPALIVE_PID" ]; then
        kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
    fi
}

ensure_sudo_credentials() {
    log_info "Refreshing sudo credentials..."
    if ! sudo -v; then
        log_fail "Failed to validate sudo credentials"
        exit 1
    fi

    # Keep sudo credentials fresh so later build/test steps do not block mid-run.
    while true; do
        sudo -n -v 2>/dev/null || exit
        sleep 60
    done &
    SUDO_KEEPALIVE_PID=$!
    trap cleanup_sudo_keepalive EXIT
}

is_nf() {
    local name=$1
    [[ " $SUPPORTED_NFS " =~ " $name " ]]
}

is_number() {
    [[ "$1" =~ ^[0-9]+$ ]]
}

# Check minimum args
if [ $# -lt 3 ]; then
    usage
fi

# Parse type
TYPE=$1
shift

# Parse optional flags first (find and remove them from args)
SKIP_DOCKER=false
SKIP_TESTALL=false
SKIP_PULL=false
REMAINING_ARGS=()

for arg in "$@"; do
    case $arg in
        --skip-docker) SKIP_DOCKER=true ;;
        --skip-testall) SKIP_TESTALL=true ;;
        --skip-pull) SKIP_PULL=true ;;
        *) REMAINING_ARGS+=("$arg") ;;
    esac
done

# Associative array to store NF -> PR list mapping
declare -A NF_PRS

# Associative array to store Library -> PR list mapping
declare -A LIB_PRS

# Variable to store main free5gc repo PR
FREE5GC_PR=""

case $TYPE in
    free5gc)
        # Format: free5gc <PR#> nf <NF1> <PR1> [<NF2> <PR2> ...]
        if [ ${#REMAINING_ARGS[@]} -lt 4 ]; then
            echo "Error: free5gc PR number and at least one NF with PR required"
            echo "Format: $0 free5gc <PR#> nf <NF1> <PR1> ..."
            usage
        fi
        
        # First argument should be the free5gc main repo PR number
        if ! is_number "${REMAINING_ARGS[0]}"; then
            echo "Error: Expected PR number after 'free5gc', got '${REMAINING_ARGS[0]}'"
            usage
        fi
        FREE5GC_PR="${REMAINING_ARGS[0]}"
        
        # Second argument should be 'nf'
        if [ "${REMAINING_ARGS[1]}" != "nf" ]; then
            echo "Error: Expected 'nf' after free5gc PR number, got '${REMAINING_ARGS[1]}'"
            usage
        fi
        
        # Parse remaining NF/PR pairs (starting from index 2)
        CURRENT_NF=""
        for ((i=2; i<${#REMAINING_ARGS[@]}; i++)); do
            arg="${REMAINING_ARGS[$i]}"
            if is_nf "$arg"; then
                CURRENT_NF="$arg"
                if [ -z "${NF_PRS[$CURRENT_NF]}" ]; then
                    NF_PRS[$CURRENT_NF]=""
                fi
            elif is_number "$arg"; then
                if [ -z "$CURRENT_NF" ]; then
                    echo "Error: PR number '$arg' without NF name"
                    usage
                fi
                if [ -z "${NF_PRS[$CURRENT_NF]}" ]; then
                    NF_PRS[$CURRENT_NF]="$arg"
                else
                    NF_PRS[$CURRENT_NF]="${NF_PRS[$CURRENT_NF]} $arg"
                fi
            else
                echo "Error: Unknown argument '$arg' (not a valid NF or PR number)"
                usage
            fi
        done
        
        # Validate that we have at least one NF with PRs
        if [ ${#NF_PRS[@]} -eq 0 ]; then
            echo "Error: No valid NF/PR pairs found"
            usage
        fi
        
        # Set TYPE to nf for later processing, but remember we have FREE5GC_PR
        TYPE="nf"
        ;;
    nf)
        # Parse NF and PR pairs from remaining args
        # Format: <NF1> <PR1> [<PR2> ...] [<NF2> <PR3> ...] [lib <LIB1> <PR1> ...]
        if [ ${#REMAINING_ARGS[@]} -lt 2 ]; then
            echo "Error: At least one NF and PR number required"
            usage
        fi
        
        CURRENT_NF=""
        CURRENT_LIB=""
        PARSING_MODE="nf"  # nf or lib
        
        for arg in "${REMAINING_ARGS[@]}"; do
            # Check if switching to lib mode
            if [ "$arg" = "lib" ]; then
                PARSING_MODE="lib"
                CURRENT_NF=""
                CURRENT_LIB=""
                continue
            fi
            
            if [ "$PARSING_MODE" = "nf" ]; then
                if is_nf "$arg"; then
                    CURRENT_NF="$arg"
                    if [ -z "${NF_PRS[$CURRENT_NF]}" ]; then
                        NF_PRS[$CURRENT_NF]=""
                    fi
                elif is_number "$arg"; then
                    if [ -z "$CURRENT_NF" ]; then
                        echo "Error: PR number '$arg' without NF name"
                        usage
                    fi
                    if [ -z "${NF_PRS[$CURRENT_NF]}" ]; then
                        NF_PRS[$CURRENT_NF]="$arg"
                    else
                        NF_PRS[$CURRENT_NF]="${NF_PRS[$CURRENT_NF]} $arg"
                    fi
                else
                    echo "Error: Unknown argument '$arg' (not a valid NF or PR number)"
                    usage
                fi
            else
                # Parsing lib mode
                if is_lib "$arg"; then
                    CURRENT_LIB="$arg"
                    if [ -z "${LIB_PRS[$CURRENT_LIB]}" ]; then
                        LIB_PRS[$CURRENT_LIB]=""
                    fi
                elif is_number "$arg"; then
                    if [ -z "$CURRENT_LIB" ]; then
                        echo "Error: PR number '$arg' without library name"
                        usage
                    fi
                    if [ -z "${LIB_PRS[$CURRENT_LIB]}" ]; then
                        LIB_PRS[$CURRENT_LIB]="$arg"
                    else
                        LIB_PRS[$CURRENT_LIB]="${LIB_PRS[$CURRENT_LIB]} $arg"
                    fi
                else
                    echo "Error: Unknown argument '$arg' (not a valid library or PR number)"
                    usage
                fi
            fi
        done
        
        # Validate that we have at least one NF with PRs
        if [ ${#NF_PRS[@]} -eq 0 ]; then
            echo "Error: No valid NF/PR pairs found"
            usage
        fi
        ;;
    lib)
        if [ ${#REMAINING_ARGS[@]} -lt 2 ]; then
            echo "Error: Library name and PR number required"
            usage
        fi
        LIBRARY="${REMAINING_ARGS[0]}"
        LIB_PR="${REMAINING_ARGS[1]}"
        # Validate library
        if [[ ! " $SUPPORTED_LIBS " =~ " $LIBRARY " ]]; then
            echo "Error: Unsupported library '$LIBRARY'"
            echo "Supported: $SUPPORTED_LIBS"
            exit 1
        fi
        ;;
    *)
        usage
        ;;
esac

# Header
echo -e "${GREEN}"
echo "╔════════════════════════════════════════╗"
echo "║       free5GC PR Test Automation       ║"
echo "╚════════════════════════════════════════╝"
echo -e "${NC}"
echo "Type: $TYPE"

if [ "$TYPE" = "nf" ]; then
    if [ -n "$FREE5GC_PR" ]; then
        echo "Main free5gc Repo PR: #$FREE5GC_PR"
    fi
    echo "NF/PR Configuration:"
    for nf in "${!NF_PRS[@]}"; do
        echo "  - $nf: PRs ${NF_PRS[$nf]}"
    done
    if [ ${#LIB_PRS[@]} -gt 0 ]; then
        echo "Library/PR Configuration:"
        for lib in "${!LIB_PRS[@]}"; do
            echo "  - $lib: PRs ${LIB_PRS[$lib]}"
        done
    fi
else
    echo "Library: $LIBRARY, PR: #$LIB_PR"
fi

echo "Skip Pull: $SKIP_PULL"
echo "Skip Docker: $SKIP_DOCKER"
echo "Skip TestAll: $SKIP_TESTALL"
echo ""

# Ensure we're in ci-test directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ensure_sudo_credentials

# Create report directory and fix permissions if needed
mkdir -p "$REPORT_DIR"
if [ ! -w "$REPORT_DIR" ]; then
    log_info "Fixing permissions on $REPORT_DIR..."
    sudo chown -R $(whoami):$(whoami) "$REPORT_DIR"
fi

# Build PR string for report filename
if [ "$TYPE" = "nf" ]; then
    PR_STR=""
    if [ -n "$FREE5GC_PR" ]; then
        PR_STR="free5gc_${FREE5GC_PR}_"
    fi
    for nf in "${!NF_PRS[@]}"; do
        prs="${NF_PRS[$nf]}"
        pr_joined="${prs// /_}"
        PR_STR="${PR_STR}${nf}_${pr_joined}_"
    done
    # Add library PRs to filename if present
    for lib in "${!LIB_PRS[@]}"; do
        prs="${LIB_PRS[$lib]}"
        pr_joined="${prs// /_}"
        PR_STR="${PR_STR}${lib}_${pr_joined}_"
    done
    PR_STR="${PR_STR%_}"  # Remove trailing underscore
else
    PR_STR="${LIBRARY}_${LIB_PR}"
fi

REPORT_FILE="$REPORT_DIR/pr_test_${PR_STR}_$(date +%Y%m%d_%H%M%S).txt"

# Start report
{
    echo "=========================================="
    echo "free5GC PR Test Report"
    echo "=========================================="
    echo "Date: $(date)"
    echo "Type: $TYPE"
    if [ "$TYPE" = "nf" ]; then
        if [ -n "$FREE5GC_PR" ]; then
            echo "Main free5gc Repo PR: #$FREE5GC_PR"
        fi
        echo "NF/PR Configuration:"
        for nf in "${!NF_PRS[@]}"; do
            echo "  - $nf: PRs ${NF_PRS[$nf]}"
        done
        if [ ${#LIB_PRS[@]} -gt 0 ]; then
            echo "Library/PR Configuration:"
            for lib in "${!LIB_PRS[@]}"; do
                echo "  - $lib: PRs ${LIB_PRS[$lib]}"
            done
        fi
    else
        echo "Library: $LIBRARY, PR: #$LIB_PR"
    fi
    echo ""
} > "$REPORT_FILE"

# ============================================================
# Step 1: Pull (if not skipped)
# ============================================================
log_step 1 "Pulling free5gc Repository"

# Fix permissions if base directory has wrong ownership (from previous sudo run)
if [ -d "base/free5gc" ] && [ ! -w "base/free5gc" ]; then
    log_info "Fixing permissions on base/free5gc (from previous sudo run)..."
    sudo chown -R $(whoami):$(whoami) base/
fi

if [ "$SKIP_PULL" = false ]; then
    log_info "Running ci-operation.sh pull..."
    ./ci-operation.sh pull
    echo "[STEP 1] Pull: SUCCESS" >> "$REPORT_FILE"
else
    log_info "Skipping pull (--skip-pull)"
    echo "[STEP 1] Pull: SKIPPED" >> "$REPORT_FILE"
fi

# ============================================================
# Step 2: Fetch/Merge PR(s)
# ============================================================
log_step 2 "Fetching and Merging PR(s)"

# Helper function to apply library PR replacement
apply_library_pr() {
    local lib_name=$1
    local lib_pr=$2
    
    log_info "Fetching $lib_name PR #$lib_pr info from GitHub API..."
    
    local PR_API_URL="https://api.github.com/repos/free5gc/$lib_name/pulls/$lib_pr"
    local PR_INFO=$(curl -s "$PR_API_URL")
    
    # Extract PR author (head.user.login) and commit hash (head.sha)
    local PR_AUTHOR=$(echo "$PR_INFO" | grep -o '"login": "[^"]*"' | head -1 | cut -d'"' -f4)
    local PR_COMMIT=$(echo "$PR_INFO" | grep -o '"sha": "[^"]*"' | head -1 | cut -d'"' -f4)
    local PR_STATE=$(echo "$PR_INFO" | grep -o '"state": "[^"]*"' | head -1 | cut -d'"' -f4)
    
    if [ -z "$PR_AUTHOR" ] || [ -z "$PR_COMMIT" ]; then
        log_fail "Failed to get $lib_name PR #$lib_pr info from GitHub API"
        return 1
    fi
    
    log_info "$lib_name PR #$lib_pr: Author=$PR_AUTHOR, Commit=${PR_COMMIT:0:12}, State=$PR_STATE"
    
    local ORIGINAL_MODULE="github.com/free5gc/$lib_name"
    local REPLACE_MODULE="github.com/$PR_AUTHOR/$lib_name@$PR_COMMIT"
    
    log_info "Replace: $ORIGINAL_MODULE => $REPLACE_MODULE"
    
    # Update all NFs
    local UPDATED_MODULES=""
    for nf in amf ausf bsf chf n3iwf nef nrf nssf pcf smf tngf udm udr upf; do
        local nf_dir="NFs/$nf"
        if [ -d "$nf_dir" ] && grep -q "$ORIGINAL_MODULE" "$nf_dir/go.mod" 2>/dev/null; then
            cd "$nf_dir"
            if go mod edit -replace "$ORIGINAL_MODULE=$REPLACE_MODULE"; then
                go mod tidy 2>/dev/null || true
                UPDATED_MODULES="$UPDATED_MODULES $nf"
            fi
            cd ../../
        fi
    done
    
    # Update test module
    if grep -q "$ORIGINAL_MODULE" "test/go.mod" 2>/dev/null; then
        cd test
        go mod edit -replace "$ORIGINAL_MODULE=$REPLACE_MODULE"
        go mod tidy 2>/dev/null || true
        UPDATED_MODULES="$UPDATED_MODULES test"
        cd ..
    fi
    
    # Update main go.mod
    if grep -q "$ORIGINAL_MODULE" "go.mod" 2>/dev/null; then
        go mod edit -replace "$ORIGINAL_MODULE=$REPLACE_MODULE"
        go mod tidy 2>/dev/null || true
        UPDATED_MODULES="$UPDATED_MODULES main"
    fi
    
    log_pass "$lib_name PR #$lib_pr applied to:$UPDATED_MODULES"
    echo "  - $lib_name #$lib_pr: REPLACED (Author: $PR_AUTHOR, Commit: ${PR_COMMIT:0:12})" >> "$SCRIPT_DIR/$REPORT_FILE"
    echo "    Updated:$UPDATED_MODULES" >> "$SCRIPT_DIR/$REPORT_FILE"
}

if [ "$TYPE" = "nf" ]; then
    echo "[STEP 2] Fetch/Merge PRs:" >> "$REPORT_FILE"
    
    # First, apply library PRs if specified (before NF merges)
    if [ ${#LIB_PRS[@]} -gt 0 ]; then
        log_info "Applying library PR replacements first..."
        cd base/free5gc
        
        for lib in "${!LIB_PRS[@]}"; do
            prs="${LIB_PRS[$lib]}"
            for pr in $prs; do
                apply_library_pr "$lib" "$pr"
            done
        done
        
        cd ../../
    fi
    
    # Then, merge main free5gc repo PR if specified
    if [ -n "$FREE5GC_PR" ]; then
        log_info "Processing main free5gc repo PR #$FREE5GC_PR..."
        
        cd base/free5gc
        
        # Create a test branch from current HEAD
        git checkout -b test-free5gc-pr-$(date +%s) 2>/dev/null || git checkout -B test-free5gc-pr-$(date +%s)
        
        log_info "Fetching and merging free5gc PR #$FREE5GC_PR..."
        
        # Fetch the PR from main free5gc repo
        git fetch origin pull/$FREE5GC_PR/head:pr-$FREE5GC_PR
        
        # Try to merge
        if git merge pr-$FREE5GC_PR --no-edit -m "Merge free5gc PR #$FREE5GC_PR for testing"; then
            log_pass "Merged free5gc PR #$FREE5GC_PR successfully"
            echo "  - free5gc #$FREE5GC_PR: MERGED" >> "../../$REPORT_FILE"
        else
            log_fail "Merge conflict for free5gc PR #$FREE5GC_PR"
            echo "  - free5gc #$FREE5GC_PR: CONFLICT" >> "../../$REPORT_FILE"
            echo ""
            echo -e "${RED}========================================${NC}"
            echo -e "${RED}MERGE CONFLICT DETECTED${NC}"
            echo -e "${RED}========================================${NC}"
            echo ""
            echo "Repo: free5gc (main), PR: #$FREE5GC_PR"
            echo "Directory: $(pwd)"
            echo ""
            echo "Please resolve the conflict manually:"
            echo "  1. cd $(pwd)"
            echo "  2. Resolve conflicts in the files listed above"
            echo "  3. git add <resolved files>"
            echo "  4. git commit"
            echo "  5. Re-run this script with --skip-pull"
            echo ""
            exit 1
        fi
        
        # Run go mod tidy after merging main repo PR
        log_info "Running go mod tidy for main free5gc repo..."
        go mod tidy || log_warn "go mod tidy failed for main free5gc repo"
        
        cd ../../
    fi
    
    # Then process NF PRs
    for nf in "${!NF_PRS[@]}"; do
        prs="${NF_PRS[$nf]}"
        log_info "Processing NF: $nf with PRs: $prs"
        
        # Enter NF directory
        cd "base/free5gc/NFs/$nf"
        
        # Create a test branch from current HEAD
        git checkout -b test-multi-pr-$(date +%s) 2>/dev/null || git checkout -B test-multi-pr-$(date +%s)
        
        # Merge each PR
        for pr in $prs; do
            log_info "Fetching and merging $nf PR #$pr..."
            
            # Fetch the PR
            git fetch origin pull/$pr/head:pr-$pr
            
            # Try to merge
            if git merge pr-$pr --no-edit -m "Merge PR #$pr for testing"; then
                log_pass "Merged $nf PR #$pr successfully"
                echo "  - $nf #$pr: MERGED" >> "../../../../$REPORT_FILE"
            else
                log_fail "Merge conflict for $nf PR #$pr"
                echo "  - $nf #$pr: CONFLICT" >> "../../../../$REPORT_FILE"
                echo ""
                echo -e "${RED}========================================${NC}"
                echo -e "${RED}MERGE CONFLICT DETECTED${NC}"
                echo -e "${RED}========================================${NC}"
                echo ""
                echo "NF: $nf, PR: #$pr"
                echo "Directory: $(pwd)"
                echo ""
                echo "Please resolve the conflict manually:"
                echo "  1. cd $(pwd)"
                echo "  2. Resolve conflicts in the files listed above"
                echo "  3. git add <resolved files>"
                echo "  4. git commit"
                echo "  5. Re-run this script with --skip-pull"
                echo ""
                exit 1
            fi
        done
        
        # Run go mod tidy after merging all PRs for this NF
        log_info "Running go mod tidy for $nf..."
        go mod tidy || log_warn "go mod tidy failed for $nf"
        
        # Return to ci-test directory
        cd ../../../../
    done
    
    # Also update test module dependencies
    log_info "Updating test module dependencies..."
    cd base/free5gc/test
    go mod tidy || log_warn "go mod tidy failed for test module"
    cd ../../../
else
    log_info "Updating library $LIBRARY for all NFs using go mod edit -replace..."
    
    # Get PR information from GitHub API
    log_info "Fetching PR #$LIB_PR info from GitHub API..."
    
    PR_API_URL="https://api.github.com/repos/free5gc/$LIBRARY/pulls/$LIB_PR"
    PR_INFO=$(curl -s "$PR_API_URL")
    
    # Extract PR author (head.user.login) and commit hash (head.sha)
    PR_AUTHOR=$(echo "$PR_INFO" | grep -o '"login": "[^"]*"' | head -1 | cut -d'"' -f4)
    PR_COMMIT=$(echo "$PR_INFO" | grep -o '"sha": "[^"]*"' | head -1 | cut -d'"' -f4)
    PR_STATE=$(echo "$PR_INFO" | grep -o '"state": "[^"]*"' | head -1 | cut -d'"' -f4)
    
    # Validate we got the info
    if [ -z "$PR_AUTHOR" ] || [ -z "$PR_COMMIT" ]; then
        log_fail "Failed to get PR info from GitHub API"
        echo "API Response: $PR_INFO"
        exit 1
    fi
    
    log_info "PR #$LIB_PR Details:"
    log_info "  Author: $PR_AUTHOR"
    log_info "  Commit: $PR_COMMIT"
    log_info "  State: $PR_STATE"
    
    # Build the replace directive
    ORIGINAL_MODULE="github.com/free5gc/$LIBRARY"
    REPLACE_MODULE="github.com/$PR_AUTHOR/$LIBRARY@$PR_COMMIT"
    
    log_info "Replace directive: $ORIGINAL_MODULE => $REPLACE_MODULE"
    
    # Update all NFs
    cd base/free5gc
    
    UPDATED_NFS=""
    for nf in amf ausf bsf chf n3iwf nef nrf nssf pcf smf tngf udm udr upf; do
        nf_dir="NFs/$nf"
        if [ -d "$nf_dir" ] && grep -q "$ORIGINAL_MODULE" "$nf_dir/go.mod" 2>/dev/null; then
            log_info "Updating $nf..."
            cd "$nf_dir"
            
            # Use go mod edit -replace
            if go mod edit -replace "$ORIGINAL_MODULE=$REPLACE_MODULE"; then
                go mod tidy
                UPDATED_NFS="$UPDATED_NFS $nf"
                log_pass "Updated $nf"
            else
                log_warn "Failed to update $nf"
            fi
            
            cd ../../
        fi
    done
    
    # Also update test module
    if grep -q "$ORIGINAL_MODULE" "test/go.mod" 2>/dev/null; then
        log_info "Updating test module..."
        cd test
        if go mod edit -replace "$ORIGINAL_MODULE=$REPLACE_MODULE"; then
            go mod tidy
            log_pass "Updated test module"
        else
            log_warn "Failed to update test module"
        fi
        cd ..
    fi
    
    # Also update main free5gc go.mod if it uses the library
    if grep -q "$ORIGINAL_MODULE" "go.mod" 2>/dev/null; then
        log_info "Updating main free5gc go.mod..."
        if go mod edit -replace "$ORIGINAL_MODULE=$REPLACE_MODULE"; then
            go mod tidy
            log_pass "Updated main free5gc module"
        else
            log_warn "Failed to update main free5gc module"
        fi
    fi
    
    cd ../../
    echo "[STEP 2] Update Library $LIBRARY PR #$LIB_PR:" >> "$REPORT_FILE"
    echo "  Author: $PR_AUTHOR" >> "$REPORT_FILE"
    echo "  Commit: ${PR_COMMIT:0:12}" >> "$REPORT_FILE"
    echo "  Replace: $ORIGINAL_MODULE => $REPLACE_MODULE" >> "$REPORT_FILE"
    echo "  Updated NFs:$UPDATED_NFS" >> "$REPORT_FILE"

fi

# ============================================================
# Step 3: Build
# ============================================================
log_step 3 "Building"

cd base/free5gc
log_info "Running make all..."
make all
log_info "Cleaning up previous processes..."
./force_kill.sh 2>/dev/null || true
cd ../../

echo "[STEP 3] Build: SUCCESS" >> "$REPORT_FILE"

# ============================================================
# Step 4: Run Tests (except TestTngf)
# ============================================================
if [ "$SKIP_TESTALL" = false ]; then
    log_step 4 "Running Unit Tests"
    
    cd base/free5gc
    
    # Create test output directory
    mkdir -p testing_output
    
    FAILED_TESTS=""
    PASSED_TESTS=""
    
    echo "" >> "../../$REPORT_FILE"
    echo "[STEP 4] Unit Tests:" >> "../../$REPORT_FILE"
    
    for test in $TEST_POOL; do
        log_info "Running $test..."
        
        # Run test and save output (like ./test.sh All does)
        if timeout $TEST_TIMEOUT sudo ./test.sh $test &> testing_output/$test.log; then
            # Check if PASS in output
            if grep -q "PASS" testing_output/$test.log; then
                log_pass "$test"
                PASSED_TESTS="$PASSED_TESTS $test"
                echo "  $test: PASS" >> "../../$REPORT_FILE"
            else
                log_fail "$test (no PASS found)"
                FAILED_TESTS="$FAILED_TESTS $test"
                echo "  $test: FAIL" >> "../../$REPORT_FILE"
            fi
        else
            log_fail "$test (timeout or error)"
            FAILED_TESTS="$FAILED_TESTS $test"
            echo "  $test: FAIL (timeout/error)" >> "../../$REPORT_FILE"
        fi
        
        # force_kill after each test
        ./force_kill.sh 2>/dev/null || true
        sleep 2
    done
    
    # Run TestTngf last (allow failure, don't stop script)
    log_info "Running TestTngf (last, timeout ${TNGF_TIMEOUT}s, allowed to fail)..."
    TNGF_RESULT=0
    timeout $TNGF_TIMEOUT sudo ./test.sh TestTngf &> testing_output/TestTngf.log || TNGF_RESULT=$?
    
    if [ $TNGF_RESULT -eq 0 ]; then
        if grep -q "PASS" testing_output/TestTngf.log; then
            log_pass "TestTngf"
            PASSED_TESTS="$PASSED_TESTS TestTngf"
            echo "  TestTngf: PASS" >> "../../$REPORT_FILE"
        else
            log_warn "TestTngf (no PASS found)"
            FAILED_TESTS="$FAILED_TESTS TestTngf"
            echo "  TestTngf: FAIL" >> "../../$REPORT_FILE"
        fi
    elif [ $TNGF_RESULT -eq 124 ]; then
        log_warn "TestTngf (timeout - continuing)"
        FAILED_TESTS="$FAILED_TESTS TestTngf"
        echo "  TestTngf: TIMEOUT (continued)" >> "../../$REPORT_FILE"
    else
        log_warn "TestTngf (error code: $TNGF_RESULT - continuing)"
        FAILED_TESTS="$FAILED_TESTS TestTngf"
        echo "  TestTngf: FAIL (exit $TNGF_RESULT)" >> "../../$REPORT_FILE"
    fi
    
    # force_kill after TestTngf
    ./force_kill.sh
    
    cd ../../
    
    # Summary
    echo ""
    log_info "Test Summary:"
    echo -e "  ${GREEN}Passed:${NC}$PASSED_TESTS"
    [ -n "$FAILED_TESTS" ] && echo -e "  ${RED}Failed:${NC}$FAILED_TESTS"
    
    echo "" >> "$REPORT_FILE"
    echo "  Summary:" >> "$REPORT_FILE"
    echo "    Passed:$PASSED_TESTS" >> "$REPORT_FILE"
    [ -n "$FAILED_TESTS" ] && echo "    Failed:$FAILED_TESTS" >> "$REPORT_FILE"
else
    log_step 4 "Skipping Unit Tests (--skip-testall)"
    echo "[STEP 4] Unit Tests: SKIPPED" >> "$REPORT_FILE"
fi

# ============================================================
# Step 5: Build Docker Images
# ============================================================
log_step 5 "Building Docker Images"

log_info "Running sudo ci-operation.sh build..."
sudo ./ci-operation.sh build

echo "[STEP 5] Docker Build: SUCCESS" >> "$REPORT_FILE"

# ============================================================
# Step 6: Docker Compose Tests
# ============================================================
if [ "$SKIP_DOCKER" = false ]; then
    log_step 6 "Running Docker Compose Tests"
    
    # Cleanup Docker environment to avoid orphan containers and network issues
    log_info "Cleaning up Docker environment..."
    sudo docker system prune -f >/dev/null 2>&1 || true
    sudo docker network prune -f >/dev/null 2>&1 || true
    
    DOCKER_FAILED=""
    DOCKER_PASSED=""
    
    echo "" >> "$REPORT_FILE"
    echo "[STEP 6] Docker Compose Tests:" >> "$REPORT_FILE"
    
    for scenario in basic ulcl-ti ulcl-mp; do
        log_info "Testing scenario: $scenario"
        
        # Determine compose file (prefer non-ci version that uses local build)
        COMPOSE_FILE="docker-compose-${scenario}.yaml"
        if [ ! -f "$COMPOSE_FILE" ]; then
            # Fallback to ci version (uses Docker Hub images)
            COMPOSE_FILE="docker-compose-ci-${scenario}.yaml"
            log_warn "Using CI compose file (Docker Hub images): $COMPOSE_FILE"
        fi
        
        log_info "Using compose file: $COMPOSE_FILE"
        
        # Up (with sudo)
        if ! sudo docker compose -f "$COMPOSE_FILE" up -d --wait --wait-timeout $DOCKER_TIMEOUT; then
            log_warn "Failed to start $scenario"
            DOCKER_FAILED="$DOCKER_FAILED $scenario"
            echo "  $scenario: FAIL (compose up failed)" >> "$REPORT_FILE"
            sudo docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
            continue
        fi
        sleep 5
        
        # Run tests
        TEST_RESULT=0
        case $scenario in
            basic)
                ./ci-test-basic.sh TestBasicCharging || TEST_RESULT=1
                ;;
            ulcl-ti)
                ./ci-test-ulcl-ti.sh TestULCLTrafficInfluence || TEST_RESULT=1
                ;;
            ulcl-mp)
                ./ci-test-ulcl-mp.sh TestULCLMultiPathUe1 || TEST_RESULT=1
                ./ci-test-ulcl-mp.sh TestULCLMultiPathUe2 || TEST_RESULT=$((TEST_RESULT + 1))
                ;;
        esac
        
        if [ $TEST_RESULT -eq 0 ]; then
            log_pass "$scenario"
            DOCKER_PASSED="$DOCKER_PASSED $scenario"
            echo "  $scenario: PASS" >> "$REPORT_FILE"
        else
            log_fail "$scenario"
            DOCKER_FAILED="$DOCKER_FAILED $scenario"
            echo "  $scenario: FAIL" >> "$REPORT_FILE"
        fi
        
        # Down
        sudo docker compose -f "$COMPOSE_FILE" down
        sleep 2
    done
    
    echo "" >> "$REPORT_FILE"
    echo "  Summary:" >> "$REPORT_FILE"
    [ -n "$DOCKER_PASSED" ] && echo "    Passed:$DOCKER_PASSED" >> "$REPORT_FILE"
    [ -n "$DOCKER_FAILED" ] && echo "    Failed:$DOCKER_FAILED" >> "$REPORT_FILE"
else
    log_step 6 "Skipping Docker Compose Tests (--skip-docker)"
    echo "[STEP 6] Docker Compose Tests: SKIPPED" >> "$REPORT_FILE"
fi

# ============================================================
# Complete
# ============================================================
echo "" >> "$REPORT_FILE"
echo "==========================================" >> "$REPORT_FILE"
echo "Test Complete: $(date)" >> "$REPORT_FILE"
echo "==========================================" >> "$REPORT_FILE"

echo ""
echo -e "${GREEN}"
echo "╔════════════════════════════════════════╗"
echo "║         PR Test Complete!              ║"
echo "╚════════════════════════════════════════╝"
echo -e "${NC}"
echo "Type: $TYPE"

if [ "$TYPE" = "nf" ]; then
    if [ -n "$FREE5GC_PR" ]; then
        echo "Main free5gc Repo PR: #$FREE5GC_PR"
    fi
    echo "NF/PR Configuration:"
    for nf in "${!NF_PRS[@]}"; do
        echo "  - $nf: PRs ${NF_PRS[$nf]}"
    done
    if [ ${#LIB_PRS[@]} -gt 0 ]; then
        echo "Library/PR Configuration:"
        for lib in "${!LIB_PRS[@]}"; do
            echo "  - $lib: PRs ${LIB_PRS[$lib]}"
        done
    fi
else
    echo "Library: $LIBRARY, PR: #$LIB_PR"
fi

echo ""
echo -e "${YELLOW}Report saved to: $REPORT_FILE${NC}"
echo ""

# Show report summary
cat "$REPORT_FILE"
