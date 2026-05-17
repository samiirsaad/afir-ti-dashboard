"""
Asset Inventory Manager
Manages known assets on the network
"""

import json
import os
from datetime import datetime


class AssetManager:
    """Manage network asset inventory"""

    def __init__(self, assets_file):
        self.assets_file = assets_file
        self._init_assets()

    def _init_assets(self):
        """Initialize assets file if not exists"""
        try:
            with open(self.assets_file, "r") as f:
                json.load(f)
                return
        except:
            pass

        default_assets = []

        try:
            os.makedirs(os.path.dirname(self.assets_file), exist_ok=True)
            with open(self.assets_file, "w") as f:
                json.dump(default_assets, f, indent=2)
        except Exception as e:
            print(f"Error initializing assets: {e}")

    def get_assets(self):
        """Get all assets"""
        try:
            with open(self.assets_file, "r") as f:
                return json.load(f)
        except:
            return []

    def get_asset(self, ip):
        """Get single asset by IP"""
        assets = self.get_assets()
        for asset in assets:
            if asset.get("ip") == ip:
                return asset
        return None

    def add_asset(self, data):
        """Add new asset"""
        assets = self.get_assets()

        ip = data.get("ip", "")
        if not ip:
            return False

        # Check if already exists
        if self.get_asset(ip):
            return False

        new_asset = {
            "ip": ip,
            "hostname": data.get("hostname", ""),
            "owner": data.get("owner", ""),
            "description": data.get("description", ""),
            "criticality": data.get("criticality", "medium"),
            "asset_type": data.get("asset_type", "unknown"),
            "added_at": datetime.now().isoformat(),
            "last_seen": None,
        }

        assets.append(new_asset)
        self._save_assets(assets)
        return True

    def update_asset(self, ip, data):
        """Update existing asset"""
        assets = self.get_assets()

        for i, asset in enumerate(assets):
            if asset.get("ip") == ip:
                # Update fields
                for key, value in data.items():
                    if key != "ip":  # Don't change IP
                        assets[i][key] = value

                assets[i]["last_seen"] = datetime.now().isoformat()
                self._save_assets(assets)
                return True

        return False

    def delete_asset(self, ip):
        """Delete asset"""
        assets = self.get_assets()
        assets = [a for a in assets if a.get("ip") != ip]
        self._save_assets(assets)
        return True

    def _save_assets(self, assets):
        """Save assets to file"""
        try:
            with open(self.assets_file, "w") as f:
                json.dump(assets, f, indent=2, default=str)
        except Exception as e:
            print(f"Error saving assets: {e}")

    def get_hostname(self, ip):
        """Get hostname for an IP if exists"""
        asset = self.get_asset(ip)
        if asset:
            return asset.get("hostname", ip)
        return ip
