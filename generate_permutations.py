"""
DNSTwist Permutation Database Generator

This module generates DNSTwist permutations and is called automatically by app.py
on startup if the permutation database doesn't exist or is outdated.

Installation required:
    pip install dnstwist
"""

import dnstwist
import json
from datetime import datetime, timedelta
import os

TRUSTED_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon",
    "facebook", "instagram", "netflix", "linkedin", "twitter",
    "yahoo", "outlook", "hotmail", "icloud", "gmail",
    "bankofamerica", "chase", "wellsfargo", "citibank"
]

DATABASE_FILE = 'dnstwist_permutations.json'
MAX_AGE_DAYS = 30  # Regenerate if older than 30 days

def should_regenerate_database():
    """
    Check if database needs to be regenerated
    Returns True if:
    - File doesn't exist
    - File is older than MAX_AGE_DAYS
    - Brands list has changed
    """
    if not os.path.exists(DATABASE_FILE):
        print("No DNSTwist database found - will generate")
        return True
    
    try:
        with open(DATABASE_FILE, 'r') as f:
            data = json.load(f)
        
        # Check if file is too old
        generated_at = datetime.fromisoformat(data['_metadata']['generated_at'])
        age = datetime.now() - generated_at
        
        if age > timedelta(days=MAX_AGE_DAYS):
            print(f"Database is {age.days} days old - will regenerate")
            return True
        
        # Check if brands list has changed
        stored_brands = set(data['_metadata'].get('brands', []))
        current_brands = set(TRUSTED_BRANDS)
        
        if stored_brands != current_brands:
            print("Brands list has changed - will regenerate")
            return True
        
        print(f"Database is up to date ({age.days} days old)")
        return False
        
    except Exception as e:
        print(f"Error reading database: {e} - will regenerate")
        return True

def generate_permutation_database(force=False):
    """
    Generate DNSTwist permutations for all trusted brands
    
    Args:
        force (bool): Force regeneration even if database exists
    """
    if not force and not should_regenerate_database():
        return True
    
    print("\n" + "="*70)
    print("GENERATING DNSTWIST PERMUTATION DATABASE")
    print("="*70)
    print(f"Brands to process: {len(TRUSTED_BRANDS)}")
    print(f"This may take 30-60 seconds...\n")
    
    database = {
        '_metadata': {
            'generated_at': datetime.now().isoformat(),
            'brands_count': len(TRUSTED_BRANDS),
            'brands': TRUSTED_BRANDS,
            'version': '1.0'
        }
    }
    
    total_permutations = 0
    failed_brands = []
    
    for idx, brand in enumerate(TRUSTED_BRANDS, 1):
        print(f"[{idx}/{len(TRUSTED_BRANDS)}] Processing {brand}.com...", end=' ')
        
        try:
            # Generate permutations using DNSTwist
            # Use the module-level function instead of DomainFuzz class
            domain = f"{brand}.com"
            
            # Create fuzzer object
            fuzzer = dnstwist.Fuzzer(domain)
            fuzzer.generate()
            
            # Extract just the domain names from results
            permutations = [result['domain'] for result in fuzzer.domains]
            
            database[brand] = {
                'permutations': permutations,
                'count': len(permutations)
            }
            
            total_permutations += len(permutations)
            print(f"{len(permutations)} permutations")
            
        except AttributeError:
            # Fallback for even older DNSTwist versions
            try:
                permutations_list = dnstwist.fuzz_domain(f"{brand}.com")
                permutations = [p for p in permutations_list if isinstance(p, str)]
                
                database[brand] = {
                    'permutations': permutations,
                    'count': len(permutations)
                }
                
                total_permutations += len(permutations)
                print(f"{len(permutations)} permutations")
            except Exception as e2:
                print(f"Error: {e2}")
                database[brand] = {
                    'permutations': [],
                    'count': 0,
                    'error': str(e2)
                }
                failed_brands.append(brand)
        except Exception as e:
            print(f"Error: {e}")
            database[brand] = {
                'permutations': [],
                'count': 0,
                'error': str(e)
            }
            failed_brands.append(brand)
    
    # Save to JSON file
    try:
        with open(DATABASE_FILE, 'w') as f:
            json.dump(database, f, indent=2)
        
        print("\n" + "="*70)
        print("GENERATION SUMMARY")
        print("="*70)
        print(f"Successfully processed: {len(TRUSTED_BRANDS) - len(failed_brands)}/{len(TRUSTED_BRANDS)} brands")
        
        if failed_brands:
            print(f"❌ Failed brands: {', '.join(failed_brands)}")
        
        print(f"Total permutations: {total_permutations:,}")
        print(f"Average per brand: {total_permutations // max(len(TRUSTED_BRANDS) - len(failed_brands), 1):,}")
        print(f"Database size: ~{total_permutations * 30 / 1024:.1f} KB")
        print(f"Saved to: {DATABASE_FILE}")
        print("="*70 + "\n")
        
        return True
        
    except Exception as e:
        print(f"\n Failed to save database: {e}")
        return False

if __name__ == "__main__":
    # Allow manual regeneration with --force flag
    import sys
    force = '--force' in sys.argv
    
    if force:
        print("Force regeneration requested")
    
    success = generate_permutation_database(force=force)
    
    if success:
        print("Database generation complete!")
    else:
        print("Database generation failed!")
        sys.exit(1)
