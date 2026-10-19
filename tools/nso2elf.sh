#!/usr/bin/env bash
# ==============================================================================
# nso2elf.sh — Conversor automatizado de binários NSO (Switch ExeFS) para ELF64
# ==============================================================================
# Uso:
#   ./tools/nso2elf.sh <arquivo_nso_ou_pasta_exefs> [diretorio_ou_arquivo_saida] [--base 0x7100000000]
# ==============================================================================

set -euo pipefail

usage() {
    cat <<EOF
Uso: $(basename "$0") <entrada_nso_ou_pasta_exefs> [saida] [--base 0xADDR]

Exemplos:
  $(basename "$0") extracted/exefs/main extracted/exefs/main.elf
  $(basename "$0") extracted/exefs/
  $(basename "$0") extracted/exefs/main --base 0x7000000000
EOF
    exit 1
}

if [[ $# -lt 1 ]]; then
    usage
fi

INPUT=""
OUTPUT=""
BASE_ADDR="0x7100000000"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            ;;
        --base)
            BASE_ADDR="$2"
            shift 2
            ;;
        *)
            if [[ -z "$INPUT" ]]; then
                INPUT="$1"
            elif [[ -z "$OUTPUT" ]]; then
                OUTPUT="$1"
            else
                echo "[erro] Argumento inesperado: $1" >&2
                usage
            fi
            shift
            ;;
    esac
done

convert_single_nso() {
    local in_file="$1"
    local out_file="$2"
    local base="$3"

    local magic
    magic=$(head -c 4 "$in_file" 2>/dev/null || true)
    if [[ "$magic" != "NSO0" ]]; then
        echo "[skip] '$in_file' não possui magic NSO0."
        return 0
    fi

    echo "[nso2elf] Convertendo '$in_file' -> '$out_file' (base: $base)..."

    if command -v nx2elf >/dev/null 2>&1 && [[ "${FORCE_INTERNAL:-0}" != "1" ]]; then
        cp -f "$in_file" "${out_file}.tmp_nso"
        nx2elf "${out_file}.tmp_nso"
        mv -f "${out_file}.tmp_nso.elf" "$out_file" 2>/dev/null || mv -f "${out_file}.tmp_nso" "$out_file"
        rm -f "${out_file}.tmp_nso"
        echo "[ok] Gerado via nx2elf: $out_file"
        return 0
    fi

    python3 - "$in_file" "$out_file" "$base" <<'PYEOF'
import ctypes
import ctypes.util
import struct
import sys

def lz4_decompress_block(src: bytes, uncompressed_size: int) -> bytes:
    try:
        import lz4.block
        return lz4.block.decompress(src, uncompressed_size=uncompressed_size)
    except ImportError:
        pass

    libname = ctypes.util.find_library("lz4") or "liblz4.so.1"
    try:
        liblz4 = ctypes.CDLL(libname)
        dst = ctypes.create_string_buffer(uncompressed_size)
        res = liblz4.LZ4_decompress_safe(
            ctypes.c_char_p(src),
            dst,
            ctypes.c_int(len(src)),
            ctypes.c_int(uncompressed_size),
        )
        if res == uncompressed_size:
            return dst.raw
    except Exception:
        pass

    s = memoryview(src)
    se = len(s)
    d = bytearray(uncompressed_size)
    sp = 0
    dp = 0
    while sp < se:
        tok = s[sp]
        sp += 1
        lit = tok >> 4
        if lit == 15:
            while True:
                b = s[sp]
                sp += 1
                lit += b
                if b != 255:
                    break
        d[dp:dp + lit] = s[sp:sp + lit]
        dp += lit
        sp += lit
        if sp >= se:
            break
        off = s[sp] | (s[sp + 1] << 8)
        sp += 2
        ml = tok & 15
        if ml == 15:
            while True:
                b = s[sp]
                sp += 1
                ml += b
                if b != 255:
                    break
        ml += 4
        mp = dp - off
        for _ in range(ml):
            d[dp] = d[mp]
            dp += 1
            mp += 1
    if dp != uncompressed_size:
        raise RuntimeError(f"Tamanho descomprimido incorreto: {dp} != {uncompressed_size}")
    return bytes(d)

def nso_to_elf(nso_path: str, elf_path: str, base_addr: int):
    with open(nso_path, "rb") as f:
        raw = f.read()

    if raw[:4] != b"NSO0":
        raise ValueError(f"{nso_path} não é um arquivo NSO0 válido")

    flags = struct.unpack_from("<I", raw, 0x0C)[0]
    build_id = raw[0x40:0x60].rstrip(b"\x00").hex()

    segs = []
    for i in range(3):
        file_off, mem_off, dec_size = struct.unpack_from("<III", raw, 0x10 + i * 0x10)
        comp_size = struct.unpack_from("<I", raw, 0x60 + i * 4)[0]
        chunk = raw[file_off:file_off + comp_size]
        if flags & (1 << i):
            chunk = lz4_decompress_block(chunk, dec_size)
        segs.append((mem_off, chunk))

    bss_size_hdr = struct.unpack_from("<I", raw, 0x3C)[0]
    text_off, text_data = segs[0]
    ro_off, ro_data = segs[1]
    data_off, data_data = segs[2]

    total_mem = data_off + len(data_data) + bss_size_hdr
    img = bytearray((total_mem + 0xFFF) & ~0xFFF)
    for off, d in segs:
        img[off:off + len(d)] = d

    mod0_off = struct.unpack_from("<I", img, 4)[0]
    dyn_off = bss_start = bss_end = eh_start = eh_end = 0
    if mod0_off + 0x1C <= len(img) and img[mod0_off:mod0_off + 4] == b"MOD0":
        rel = lambda idx: mod0_off + struct.unpack_from("<i", img, mod0_off + 4 + idx * 4)[0]
        dyn_off, bss_start, bss_end, eh_start, eh_end, _ = [rel(i) for i in range(6)]

    bss_vaddr = bss_start if bss_start >= data_off + len(data_data) else (data_off + len(data_data))
    bss_sz = (bss_end - bss_start) if (bss_end > bss_start) else bss_size_hdr

    dyn_tags = {}
    dyn_size = 0
    if dyn_off and dyn_off < len(img):
        p = dyn_off
        while p + 16 <= len(img):
            tag, val = struct.unpack_from("<QQ", img, p)
            p += 16
            dyn_size += 16
            if tag == 0:
                break
            dyn_tags.setdefault(tag, val)

    FILE_BASE = 0x1000
    image_file_size = data_off + len(data_data)

    phdrs = []
    phdrs.append((1, 5, FILE_BASE + text_off, base_addr + text_off, base_addr + text_off, len(text_data), len(text_data), 0x1000))
    phdrs.append((1, 4, FILE_BASE + ro_off, base_addr + ro_off, base_addr + ro_off, len(ro_data), len(ro_data), 0x1000))
    phdrs.append((1, 6, FILE_BASE + data_off, base_addr + data_off, base_addr + data_off, len(data_data), len(data_data) + bss_sz, 0x1000))
    if dyn_off and dyn_size:
        phdrs.append((2, 6, FILE_BASE + dyn_off, base_addr + dyn_off, base_addr + dyn_off, dyn_size, dyn_size, 0x8))

    shstr = bytearray(b"\x00")
    def add_str(s: str) -> int:
        idx = len(shstr)
        shstr.extend(s.encode("ascii") + b"\x00")
        return idx

    shdrs = []
    shdrs.append((0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    shdrs.append((add_str(".text"), 1, 6, base_addr + text_off, FILE_BASE + text_off, len(text_data), 0, 0, 4, 0))
    shdrs.append((add_str(".rodata"), 1, 2, base_addr + ro_off, FILE_BASE + ro_off, len(ro_data), 0, 0, 8, 0))
    shdrs.append((add_str(".data"), 1, 3, base_addr + data_off, FILE_BASE + data_off, len(data_data), 0, 0, 8, 0))
    shdrs.append((add_str(".bss"), 8, 3, base_addr + bss_vaddr, FILE_BASE + image_file_size, bss_sz, 0, 0, 8, 0))

    dynstr_idx = 0
    dynsym_idx = 0
    if 5 in dyn_tags and 10 in dyn_tags:
        st_off, st_sz = dyn_tags[5], dyn_tags[10]
        dynstr_idx = len(shdrs)
        shdrs.append((add_str(".dynstr"), 3, 2, base_addr + st_off, FILE_BASE + st_off, st_sz, 0, 0, 1, 0))

    if 6 in dyn_tags and 4 in dyn_tags:
        sym_off = dyn_tags[6]
        hash_off = dyn_tags[4]
        nchain = struct.unpack_from("<I", img, hash_off + 4)[0] if hash_off + 8 <= len(img) else 0
        if nchain > 0:
            dynsym_idx = len(shdrs)
            shdrs.append((add_str(".dynsym"), 11, 2, base_addr + sym_off, FILE_BASE + sym_off, nchain * 24, dynstr_idx, 1, 8, 24))

    if dyn_off and dyn_size:
        shdrs.append((add_str(".dynamic"), 6, 3, base_addr + dyn_off, FILE_BASE + dyn_off, dyn_size, dynstr_idx, 0, 8, 16))

    if 7 in dyn_tags and 8 in dyn_tags:
        r_off, r_sz = dyn_tags[7], dyn_tags[8]
        shdrs.append((add_str(".rela.dyn"), 4, 2, base_addr + r_off, FILE_BASE + r_off, r_sz, dynsym_idx, 0, 8, 24))

    if 23 in dyn_tags and 2 in dyn_tags:
        j_off, j_sz = dyn_tags[23], dyn_tags[2]
        shdrs.append((add_str(".rela.plt"), 4, 2, base_addr + j_off, FILE_BASE + j_off, j_sz, dynsym_idx, 0, 8, 24))

    if eh_start and eh_end > eh_start and eh_end <= image_file_size:
        shdrs.append((add_str(".eh_frame_hdr"), 1, 2, base_addr + eh_start, FILE_BASE + eh_start, eh_end - eh_start, 0, 0, 4, 0))

    shstr_name = add_str(".shstrtab")
    shstr_off = (FILE_BASE + image_file_size + 7) & ~7
    shstrtab_idx = len(shdrs)
    shdrs.append((shstr_name, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0))

    shoff = (shstr_off + len(shstr) + 7) & ~7

    out = bytearray(shoff + len(shdrs) * 64)
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        out,
        0,
        e_ident,
        3,                      # ET_DYN
        183,                    # EM_AARCH64
        1,
        base_addr + text_off,
        64,
        shoff,
        0,
        64,
        56,
        len(phdrs),
        64,
        len(shdrs),
        shstrtab_idx,
    )

    for i, ph in enumerate(phdrs):
        struct.pack_into("<IIQQQQQQ", out, 64 + i * 56, *ph)

    out[FILE_BASE:FILE_BASE + image_file_size] = img[:image_file_size]
    out[shstr_off:shstr_off + len(shstr)] = shstr

    for i, sh in enumerate(shdrs):
        struct.pack_into("<IIQQQQIIQQ", out, shoff + i * 64, *sh)

    with open(elf_path, "wb") as f:
        f.write(out)

    print(
        f"[ok] {elf_path} (BuildID: {build_id[:16]}..., "
        f".text=0x{len(text_data):x}, .rodata=0x{len(ro_data):x}, "
        f".data=0x{len(data_data):x}, .bss=0x{bss_sz:x})"
    )

if __name__ == "__main__":
    nso_to_elf(sys.argv[1], sys.argv[2], int(sys.argv[3], 0))
PYEOF
}

if [[ -d "$INPUT" ]]; then
    OUT_DIR="${OUTPUT:-$INPUT}"
    mkdir -p "$OUT_DIR"
    count=0
    for f in "$INPUT"/*; do
        [[ -f "$f" ]] || continue
        base_name=$(basename "$f")
        if [[ "$base_name" == *.elf || "$base_name" == *.npdm ]]; then
            continue
        fi
        mod_base="$BASE_ADDR"
        if [[ "$base_name" == "main" && "$BASE_ADDR" == "0x7100000000" ]]; then
            mod_base="0x7000000000"
        elif [[ "$base_name" == "sdk" && "$BASE_ADDR" == "0x7100000000" ]]; then
            mod_base="0x7004000000"
        fi
        convert_single_nso "$f" "$OUT_DIR/${base_name}.elf" "$mod_base"
        count=$((count + 1))
    done
    echo "[nso2elf] Processamento concluído ($count arquivo(s) verificados em '$INPUT')."
elif [[ -f "$INPUT" ]]; then
    OUT_FILE="${OUTPUT:-${INPUT}.elf}"
    mkdir -p "$(dirname "$OUT_FILE")"
    convert_single_nso "$INPUT" "$OUT_FILE" "$BASE_ADDR"
else
    echo "[erro] Caminho não encontrado: '$INPUT'" >&2
    exit 1
fi
