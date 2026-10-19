# MK8DRecomp

Recompilação estática e runtime nativo em C/C++ para **Mario Kart 8 Deluxe** (v1.0.0), baseado na arquitetura do [LASRecomp](https://github.com/peiikai/LASRecomp).

> **Status:** Em estágio inicial de desenvolvimento (configuração do pipeline AArch64 $\to$ C, análise de binários e adaptação da camada HLE).

---

## Visão Geral da Arquitetura

- **`tools/`**: Gerador de código e ferramentas de análise estática:
  - `nso.py`: Loader e descompressor de módulos NSO0 (`.text`, `.rodata`, `.data`, `MOD0`, `.dynamic`).
  - `nso2elf.sh`: Script utilitário para converter binários NSO em arquivos `.elf` completos para análise no Ghidra.
  - `analyze.py`: Descoberta de fronteiras de funções e censo de instruções AArch64.
  - `gen.py` / `lifter.py` / `simd_c.py`: Tradutor estático de AArch64 + NEON/FP para código C portável.
  - `patches.py`: Patches pontuais por instrução.
- **`runtime/`**: Camada de execução nativa:
  - Emulação leve do kernel Horizon (`svc*`, threads `pthread`, sincronização e mapeamento de memória 1:1).
  - Serviços IPC (`sm:`, `fsp-srv`, `appletOE`, `audren:u`, `audout:u`, `hid`, `time`, `acc:u0`, `set`).
  - Implementação HLE da API gráfica **NVN** + tradutor de shaders **Maxwell $\to$ SPIR-V** sobre **Vulkan** e **SDL3**.

---

## Estrutura Esperada dos Arquivos do Jogo

Os arquivos extraídos da versão **1.0.0** do jogo (não incluídos no repositório) devem ficar em `extracted/`:

```text
extracted/
├── exefs/
│   ├── main
│   ├── main.npdm
│   ├── rtld
│   ├── sdk
│   └── subsdk0 ...
└── romfs/ (ou romfs.bin)
```

---

## Comandos Úteis

### 1. Converter NSO para ELF (para análise no Ghidra)
```bash
./tools/nso2elf.sh extracted/exefs/
```

### 2. Analisar funções e instruções de um binário NSO
```bash
python3 tools/analyze.py extracted/exefs/main --census
```

### 3. Gerar o código C recompilado
```bash
make gen
```

---

## Licença

Distribuído sob a licença MIT (veja [LICENSE](LICENSE)). Nenhum código, binário ou asset proprietário faz parte deste repositório.
