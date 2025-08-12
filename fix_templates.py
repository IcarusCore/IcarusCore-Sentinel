#!/usr/bin/env python3
"""
Fix template compatibility issues for different Python versions
"""

import os
import re

def fix_actors_template():
    """Fix the actors.html template for Python 3.12 compatibility"""
    template_path = 'templates/actors.html'
    
    if not os.path.exists(template_path):
        print(f"Template {template_path} not found!")
        return
    
    with open(template_path, 'r') as f:
        content = f.read()
    
    # Remove any remaining complex Jinja2 expressions
    fixes = [
        # Fix selectattr with match (not supported in all versions)
        (r'\{\% set apt_count = actors\|selectattr\(.*?\).*?\%\}', 
         '''{% set apt_count = 0 %}
    {% for actor in actors %}
        {% if 'APT' in actor.name %}
            {% set apt_count = apt_count + 1 %}
        {% endif %}
    {% endfor %}'''),
        
        # Fix map with unique
        (r'actors\|map\(attribute=\'country\'\)\|unique\|list\|length',
         '''{% set countries = [] %}
    {% for actor in actors %}
        {% if actor.country and actor.country not in countries %}
            {% set _ = countries.append(actor.country) %}
        {% endif %}
    {% endfor %}
    {{ countries|length }}'''),
        
        # Fix selectattr with equalto
        (r'actors\|selectattr\(\'sophistication\', \'equalto\', \'High\'\)\|list\|length',
         '''{% set high_count = 0 %}
    {% for actor in actors %}
        {% if actor.sophistication == 'High' %}
            {% set high_count = high_count + 1 %}
        {% endif %}
    {% endfor %}
    {{ high_count }}''')
    ]
    
    for pattern, replacement in fixes:
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE | re.DOTALL)
    
    # Write back the fixed content
    with open(template_path, 'w') as f:
        f.write(content)
    
    print(f"Fixed {template_path}")

def fix_tools_template():
    """Fix the tools.html template"""
    template_path = 'templates/tools.html'
    
    if not os.path.exists(template_path):
        print(f"Template {template_path} not found!")
        return
    
    with open(template_path, 'r') as f:
        content = f.read()
    
    # Fix any remaining method calls in templates
    fixes = [
        # Fix get_risk_level method calls
        (r'tool\.get_risk_level\(\).*?else.*?\'Low\'', 'tool.get("risk_level", "Medium")'),
        (r'if.*?tool\.get_risk_level.*?else.*?\'Low\'.*?==', 'if tool.get("risk_level", "Medium") ==')
    ]
    
    for pattern, replacement in fixes:
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE | re.DOTALL)
    
    with open(template_path, 'w') as f:
        f.write(content)
    
    print(f"Fixed {template_path}")

def main():
    print("Fixing template compatibility issues...")
    fix_actors_template()
    fix_tools_template()
    print("Template fixes complete!")

if __name__ == "__main__":
    main()