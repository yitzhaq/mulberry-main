#!/usr/bin/env python3
"""Generate CEmojiTable.h from CLDR annotations XML.

Usage: generate-emoji-table.py <output.h> <annotations.xml> [annotations2.xml ...]

Parses Unicode CLDR annotation files and generates a sorted C lookup
table mapping codepoint sequences to their CLDR short names (TTS
annotations). Accepts multiple input files — use both annotations/en.xml
and annotationsDerived/en.xml to include country flags and other
multi-codepoint sequences.
"""

import sys
import xml.etree.ElementTree as ET


def codepoints_from_cp(cp_str):
    """Convert a cp attribute (raw UTF-8 string) to a list of codepoints."""
    return [ord(c) for c in cp_str]


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <output.h> <annotations.xml> [...]",
              file=sys.stderr)
        sys.exit(1)

    output_path = sys.argv[1]
    xml_paths = sys.argv[2:]

    entries = []
    for xml_path in xml_paths:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        for ann in root.iter("annotation"):
            if ann.get("type") != "tts":
                continue
            cp_str = ann.get("cp", "")
            name = ann.text.strip() if ann.text else ""
            if not cp_str or not name:
                continue

            cps = codepoints_from_cp(cp_str)
            if not cps:
                continue

            # Skip pure Latin-1 single characters
            if len(cps) == 1 and cps[0] < 0x100:
                continue

            entries.append((cps, name))

    # Deduplicate by codepoint sequence (later files win)
    seen = {}
    for cps, name in entries:
        key = tuple(cps)
        seen[key] = (cps, name)
    entries = list(seen.values())

    # Sort by first codepoint, then by sequence length
    entries.sort(key=lambda e: (e[0][0], len(e[0]), e[0]))

    with open(output_path, "w") as f:
        f.write("// Auto-generated from CLDR annotations — do not edit\n")
        f.write("// Source: unicode-cldr-core annotations + annotationsDerived\n\n")
        f.write("#ifndef __CEMOJITABLE__MULBERRY__\n")
        f.write("#define __CEMOJITABLE__MULBERRY__\n\n")
        f.write("#include <stdint.h>\n")
        f.write("#include <stddef.h>\n\n")

        f.write("struct SEmojiEntry\n")
        f.write("{\n")
        f.write("\tconst uint32_t*\tcodepoints;\n")
        f.write("\tuint8_t\t\t\tlength;\n")
        f.write("\tconst char*\t\tname;\n")
        f.write("};\n\n")

        # Write codepoint sequence arrays
        for i, (cps, name) in enumerate(entries):
            hex_cps = ", ".join(f"0x{cp:04X}" for cp in cps)
            f.write(f"static const uint32_t cEmojiSeq_{i}[] = {{ {hex_cps} }};\n")

        f.write("\n")

        # Write the main table
        f.write("static const SEmojiEntry cEmojiTable[] = {\n")
        for i, (cps, name) in enumerate(entries):
            escaped_name = name.replace("\\", "\\\\").replace('"', '\\"')
            f.write(f'\t{{ cEmojiSeq_{i}, {len(cps)}, "{escaped_name}" }},\n')
        f.write("};\n\n")

        f.write("static const size_t cEmojiTableSize = "
                "sizeof(cEmojiTable) / sizeof(SEmojiEntry);\n\n")

        f.write("#endif\n")

    print(f"Generated {len(entries)} emoji entries in {output_path}")


if __name__ == "__main__":
    main()
