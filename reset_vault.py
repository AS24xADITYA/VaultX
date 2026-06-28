import os
import glob

def reset_vault():
    files_to_remove = [
        "vault.db",
        "master.json",
        "kdf_salt.bin",
        "totp_config.json",
        "canary.json"
    ]
    
    for f in files_to_remove:
        if os.path.exists(f):
            print(f"Removing {f}...")
            os.remove(f)
            
    # Also remove any decoy files just in case
    for f in glob.glob("*_decoy*"):
        print(f"Removing {f}...")
        os.remove(f)
        
    print("Vault reset complete. Ready for fresh setup.")

if __name__ == "__main__":
    reset_vault()
