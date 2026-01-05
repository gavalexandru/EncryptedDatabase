import os
import json

class DatabaseManager:
    def __init__(self, base_dir="db_storage"):
        self.base_dir = base_dir
        self.vault_path = os.path.join(self.base_dir, "vault")
        self.metadata_file = os.path.join(self.base_dir, "metadata.json")

    def setup_storage(self):
        if not os.path.exists(self.vault_path):
            os.makedirs(self.vault_path)

        if not os.path.exists(self.metadata_file):
            initial_schema = {
                "next_id": 1,  
                "files": []
            }
            with open(self.metadata_file, 'w') as f:
                json.dump(initial_schema, f, indent=4)
    
    def validate_connectivity(self):
        vault_exists = os.path.exists(self.vault_path)
        metadata_exists = os.path.exists(self.metadata_file)
        
        return vault_exists and metadata_exists
