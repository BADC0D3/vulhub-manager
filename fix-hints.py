#!/usr/bin/env python3
"""
Fix hint numbering in tutorial markdown files.
Ensures hints are numbered sequentially within each exercise/section.
"""

import re
import os
from pathlib import Path

def fix_hint_numbering(content):
    """Fix hint numbering to be sequential within each section."""
    lines = content.split('\n')
    fixed_lines = []
    
    # Track current section and hint count
    current_section = None
    hint_count = 0
    
    for i, line in enumerate(lines):
        # Detect new section (### heading)
        if line.startswith('### '):
            current_section = line
            hint_count = 0
            fixed_lines.append(line)
        # Detect hint line
        elif line.startswith(':::hint'):
            # Extract the hint content after :::hint
            hint_match = re.match(r':::hint\s+(.+?)(?:Hint\s+\d+:)?(.*)$', line)
            if hint_match:
                emoji_part = hint_match.group(1).strip()
                # Remove any existing "Hint X:" from the emoji part
                emoji_part = re.sub(r'Hint\s+\d+:\s*$', '', emoji_part).strip()
                
                # Get the rest of the hint title (after the colon)
                rest_match = re.search(r'Hint\s+\d+:\s*(.*)$', line)
                if rest_match:
                    hint_title = rest_match.group(1)
                else:
                    # If no hint title found, keep the line as is
                    hint_title = ""
                
                hint_count += 1
                
                if hint_title:
                    fixed_line = f":::hint {emoji_part} Hint {hint_count}: {hint_title}"
                else:
                    fixed_line = f":::hint {emoji_part} Hint {hint_count}"
                
                fixed_lines.append(fixed_line)
            else:
                # If the pattern doesn't match, keep the line as is
                fixed_lines.append(line)
        else:
            fixed_lines.append(line)
    
    return '\n'.join(fixed_lines)

def process_file(filepath):
    """Process a single markdown file to fix hint numbering."""
    print(f"Processing {filepath}...")
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Count hints before
    hints_before = len(re.findall(r':::hint.*Hint\s+\d+:', content))
    
    # Fix the content
    fixed_content = fix_hint_numbering(content)
    
    # Count hints after
    hints_after = len(re.findall(r':::hint.*Hint\s+\d+:', fixed_content))
    
    # Only write if something changed
    if content != fixed_content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(fixed_content)
        print(f"  ✓ Fixed {filepath} ({hints_before} → {hints_after} hints)")
        return True
    else:
        print(f"  - No changes needed for {filepath}")
        return False

def main():
    """Main function to process tutorial files."""
    import sys
    
    # Check if a specific file was provided
    if len(sys.argv) > 1:
        # Process a single file
        filepath = Path(sys.argv[1])
        if filepath.exists():
            process_file(filepath)
        else:
            print(f"Error: File {filepath} not found!")
    else:
        # Process all tutorial files
        docs_dir = Path("/home/badc0d3/repo/vulhubWeb/docs/learning")
        
        if not docs_dir.exists():
            print(f"Error: Directory {docs_dir} not found!")
            return
        
        # Process all .md files except README.md
        files_processed = 0
        files_changed = 0
        
        for md_file in docs_dir.glob("*.md"):
            if md_file.name != "README.md":
                files_processed += 1
                if process_file(md_file):
                    files_changed += 1
        
        print(f"\nSummary:")
        print(f"  Files processed: {files_processed}")
        print(f"  Files changed: {files_changed}")

if __name__ == "__main__":
    main() 