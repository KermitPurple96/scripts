#!/usr/bin/env python3
# pip install eml-parser

import sys
import json
from eml_parser import EmlParser

def default_serializer(obj):
    """Convierte objetos no serializables a string."""
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    return str(obj)

def main():
    if len(sys.argv) < 2:
        print(f"Uso: {sys.argv[0]} archivo.eml")
        sys.exit(1)

    eml_file = sys.argv[1]

    try:
        with open(eml_file, 'rb') as f:
            raw_email = f.read()

        # Crear parser
        parser = EmlParser(include_raw_body=True, include_attachment_data=True)
        parsed_eml = parser.decode_email_bytes(raw_email)

        # Imprimir JSON legible
        print(json.dumps(parsed_eml, indent=4, ensure_ascii=False, default=default_serializer))

    except Exception as e:
        print(f"[!] Error procesando {eml_file}: {e}")

if __name__ == "__main__":
    main()
