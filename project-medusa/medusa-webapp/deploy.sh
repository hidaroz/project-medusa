#!/bin/bash
set -euo pipefail

# MEDUSA Webapp Deployment Script for fly.io
# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_section() {
    echo -e "\n${BLUE}===${NC} $1 ${BLUE}===${NC}\n"
}

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check prerequisites
check_prerequisites() {
    log_section "Checking Prerequisites"
    
    # Check if flyctl is installed
    if ! command -v flyctl &> /dev/null; then
        log_error "flyctl is not installed"
        log_info "Install it from: https://fly.io/docs/hands-on/install-flyctl/"
        exit 1
    fi
    
    log_info "✅ flyctl is installed ($(flyctl version))"
    
    # Check if logged in
    if ! flyctl auth whoami &> /dev/null; then
        log_error "Not logged in to fly.io"
        log_info "Run: flyctl auth login"
        exit 1
    fi
    
    log_info "✅ Logged in to fly.io ($(flyctl auth whoami))"
    
    # Check if fly.toml exists
    if [ ! -f fly.toml ]; then
        log_error "fly.toml not found in current directory"
        exit 1
    fi
    
    log_info "✅ fly.toml configuration found"
}

# Validate configuration
validate_config() {
    log_section "Validating Configuration"
    
    # Check if API URL is set in fly.toml
    if grep -q "NEXT_PUBLIC_MEDUSA_API_URL" fly.toml; then
        API_URL=$(grep "NEXT_PUBLIC_MEDUSA_API_URL" fly.toml | cut -d "'" -f 2)
        log_info "API URL: $API_URL"
        
        if [[ "$API_URL" == *"localhost"* ]] || [[ "$API_URL" == *"127.0.0.1"* ]]; then
            log_warning "API URL points to localhost - this won't work in production!"
            log_info "Update NEXT_PUBLIC_MEDUSA_API_URL in fly.toml to your deployed API URL"
            read -p "Continue anyway? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
    else
        log_warning "NEXT_PUBLIC_MEDUSA_API_URL not found in fly.toml"
    fi
    
    log_info "✅ Configuration validated"
}

# Check if app exists
check_app_exists() {
    log_section "Checking Fly App Status"
    
    APP_NAME=$(grep "^app" fly.toml | cut -d "'" -f 2)
    
    if flyctl apps list | grep -q "$APP_NAME"; then
        log_info "✅ App '$APP_NAME' already exists"
        return 0
    else
        log_warning "App '$APP_NAME' does not exist"
        return 1
    fi
}

# Create new app
create_app() {
    log_section "Creating New Fly App"
    
    APP_NAME=$(grep "^app" fly.toml | cut -d "'" -f 2)
    REGION=$(grep "^primary_region" fly.toml | cut -d "'" -f 2)
    
    log_info "Creating app: $APP_NAME in region: $REGION"
    
    flyctl apps create "$APP_NAME" --org personal
    
    log_info "✅ App created successfully"
}

# Deploy application
deploy_app() {
    log_section "Deploying Application"
    
    log_info "Building and deploying to fly.io..."
    log_info "This may take a few minutes..."
    
    flyctl deploy --ha=false
    
    log_info "✅ Deployment complete!"
}

# Show app info
show_info() {
    log_section "Deployment Information"
    
    APP_NAME=$(grep "^app" fly.toml | cut -d "'" -f 2)
    
    log_info "App Name: $APP_NAME"
    log_info "URL: https://${APP_NAME}.fly.dev"
    log_info ""
    log_info "Useful commands:"
    log_info "  View logs:   flyctl logs"
    log_info "  SSH access:  flyctl ssh console"
    log_info "  App status:  flyctl status"
    log_info "  Open app:    flyctl open"
    log_info "  Scale app:   flyctl scale count 2"
    log_info ""
}

# Main execution
main() {
    log_section "MEDUSA Webapp Deployment"
    
    check_prerequisites
    validate_config
    
    # Check if app exists, create if not
    if ! check_app_exists; then
        read -p "Create new app? (Y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            create_app
        else
            log_error "Cannot deploy without an app"
            exit 1
        fi
    fi
    
    # Deploy
    deploy_app
    
    # Show info
    show_info
    
    log_info "✅ Deployment process complete!"
}

# Run main function
main "$@"

