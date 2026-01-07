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
    
    def add_file_entry(self, filename, encrypted_name, key_id):
        with open(self.metadata_file, "r") as f:
            data = json.load(f)

        uid = data.get("next_id", 1)
        
        new_entry = {
            "uid": uid,
            "filename": os.path.abspath(filename), 
            "encrypted_name": encrypted_name,
            "encryption_method": "RSA-2048-OAEP",
            "key_id": key_id
        }

        data["files"].append(new_entry)
        data["next_id"] = uid + 1

        with open(self.metadata_file, "w") as f:
            json.dump(data, f, indent=4)

        return uid
    
    def find_all_matches(self, search_name):
        with open(self.metadata_file, "r") as f:
            data = json.load(f)

        results = [] 

        for entry in data["files"]: 
            file_name = os.path.basename(entry["filename"]) 
            if file_name == search_name:
                results.append(entry)
            
        return results
    
    def delete_by_uid(self, uid):
        with open(self.metadata_file, "r") as f:
            data = json.load(f)

        target = None

        for entry in data["files"]: 
            if entry["uid"] == uid:
                target = entry
                break 

        if target is None:
            return False

        path = os.path.join(self.vault_path, target["encrypted_name"])
        if os.path.exists(path):
            os.remove(path)

        updated_files = []
        for file_entry in data["files"]:
            if not (file_entry["uid"] == uid):
                updated_files.append(file_entry)

        data["files"] = updated_files
        
        with open(self.metadata_file, "w") as f:
            json.dump(data, f, indent=4)

        return True