#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         VulhubWeb Docker Image Pull Script             ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed or not in PATH${NC}"
    exit 1
fi

# Find all docker-compose files
echo -e "${YELLOW}Searching for docker-compose files...${NC}"
compose_files=$(find vulnerabilities -name "docker-compose.yml" -o -name "docker-compose.yaml" 2>/dev/null)

if [ -z "$compose_files" ]; then
    echo -e "${RED}No docker-compose files found in vulnerabilities directory${NC}"
    exit 1
fi

# Extract all unique images
echo -e "${YELLOW}Extracting image names...${NC}"
all_images=""
file_count=0
build_only_count=0

while IFS= read -r compose_file; do
    if [ -f "$compose_file" ]; then
        # Check if file has build-only services (no image directive)
        if grep -q "build:" "$compose_file" && ! grep -q "image:" "$compose_file"; then
            echo -e "${YELLOW}⚠ Skipping $compose_file (build-only, no images to pull)${NC}"
            ((build_only_count++))
            continue
        fi
        
        # Extract image names using grep and sed
        # Handles both "image: name" and "image: 'name'" formats
        images=$(grep -E '^\s*image:' "$compose_file" | sed -E 's/^\s*image:\s*["\x27]?([^"\x27]+)["\x27]?/\1/' | tr -d '\r')
        if [ ! -z "$images" ]; then
            all_images+="$images"$'\n'
            ((file_count++))
        fi
    fi
done <<< "$compose_files"

if [ $build_only_count -gt 0 ]; then
    echo -e "${YELLOW}Note: Skipped $build_only_count docker-compose files that only have build contexts${NC}"
fi

# Get unique images and sort them
unique_images=$(echo "$all_images" | grep -v '^$' | sort -u)
image_count=$(echo "$unique_images" | grep -v '^$' | wc -l)

echo -e "${GREEN}Found $file_count docker-compose files${NC}"
echo -e "${GREEN}Found $image_count unique Docker images${NC}"
echo ""

# Display all images that will be pulled
echo -e "${BLUE}Images to be pulled:${NC}"
echo "$unique_images" | grep -v '^$' | nl -w2 -s'. '
echo ""

# Ask for confirmation
read -p "Do you want to pull all these images? This may take a while and use significant bandwidth. (y/N) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Operation cancelled${NC}"
    exit 0
fi

echo ""
echo -e "${BLUE}Starting image pull process...${NC}"
echo ""

# Pull each image
success_count=0
failed_count=0
failed_images=""

while IFS= read -r image; do
    if [ ! -z "$image" ]; then
        echo -e "${YELLOW}Pulling: $image${NC}"
        if docker pull "$image"; then
            echo -e "${GREEN}✓ Successfully pulled: $image${NC}"
            ((success_count++))
        else
            echo -e "${RED}✗ Failed to pull: $image${NC}"
            ((failed_count++))
            failed_images+="$image"$'\n'
        fi
        echo ""
    fi
done <<< "$unique_images"

# Summary
echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                      Summary                           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
echo -e "${GREEN}Successfully pulled: $success_count images${NC}"
echo -e "${RED}Failed to pull: $failed_count images${NC}"

if [ $failed_count -gt 0 ]; then
    echo ""
    echo -e "${RED}Failed images:${NC}"
    echo "$failed_images" | grep -v '^$' | nl -w2 -s'. '
fi

# Show disk usage
echo ""
echo -e "${BLUE}Docker disk usage:${NC}"
docker system df

echo ""
echo -e "${GREEN}Done!${NC}"
echo ""
echo -e "${YELLOW}Tip: To remove unused images later, run:${NC}"
echo "docker image prune -a" 