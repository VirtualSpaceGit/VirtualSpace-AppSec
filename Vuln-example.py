import os
import json
import zlib
import struct
import hashlib
from typing import Dict, Any, Optional

class DataSerializer:
    VERSION = 2
    MAGIC = b'DS02'
    
    def __init__(self):
        self.compression_enabled = True
        self.max_size = 1024 * 1024  # 1MB
        
    def serialize(self, data: Dict[str, Any]) -> bytes:
        json_data = json.dumps(data, separators=(',', ':'))
        json_bytes = json_data.encode('utf-8')
        
        if self.compression_enabled and len(json_bytes) > 100:
            compressed = zlib.compress(json_bytes, 6)
            if len(compressed) < len(json_bytes) * 0.9:
                json_bytes = compressed
                is_compressed = 1
            else:
                is_compressed = 0
        else:
            is_compressed = 0
            
        checksum = hashlib.sha256(json_bytes).digest()[:4]

        header = struct.pack('<4sHBBI', 
            self.MAGIC,
            self.VERSION,
            is_compressed,
            0,  # reserved
            len(json_bytes)
        )
        
        return header + checksum + json_bytes
    
    def deserialize(self, data: bytes) -> Optional[Dict[str, Any]]:
        if len(data) < 17:
            return None
            
        magic, version, is_compressed, reserved, size = struct.unpack('<4sHBBI', data[:13])
        
        if magic != self.MAGIC or version != self.VERSION:
            return None
            
        if size > self.max_size:
            return None

        stored_checksum = data[13:17]
        payload = data[17:17+size]
        if len(payload) != size:
            return None

        if hashlib.sha256(payload).digest()[:4] != stored_checksum:
            return None
            
        try:
            json_bytes = zlib.decompress(payload) if is_compressed else payload
                
            return json.loads(json_bytes.decode('utf-8'))
        except:
            return None

class ConfigStore:
    def __init__(self, base_path: str = "./configs"):
        self.base_path = base_path
        self.serializer = DataSerializer()
        os.makedirs(base_path, exist_ok=True)
        
    def save(self, name: str, config: Dict[str, Any]) -> bool:
        if not name.replace('_', '').replace('-', '').isalnum():
            return False
            
        path = os.path.join(self.base_path, f"{name}.dat")
        try:
            data = self.serializer.serialize(config)
            with open(path, 'wb') as f:
                f.write(data)
            return True
        except:
            return False