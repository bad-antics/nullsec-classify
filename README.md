# NullSec Classify

<div align="center">

```
 ██████╗██╗      █████╗ ███████╗███████╗██╗███████╗██╗   ██╗
██╔════╝██║     ██╔══██╗██╔════╝██╔════╝██║██╔════╝╚██╗ ██╔╝
██║     ██║     ███████║███████╗███████╗██║█████╗   ╚████╔╝ 
██║     ██║     ██╔══██║╚════██║╚════██║██║██╔══╝    ╚██╔╝  
╚██████╗███████╗██║  ██║███████║███████║██║██║        ██║   
 ╚═════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝╚═╝        ╚═╝   
```

**Hardened Malware Classification Engine in OCaml**

[![OCaml](https://img.shields.io/badge/OCaml-EC6813?style=for-the-badge&logo=ocaml&logoColor=white)](https://ocaml.org/)
[![Security](https://img.shields.io/badge/Security-Maximum-red?style=for-the-badge)](https://github.com/bad-antics)
[![NullSec](https://img.shields.io/badge/NullSec-Framework-purple?style=for-the-badge)](https://github.com/bad-antics)

</div>

## Security Features Features

### Strong Static Type System
- **Algebraic Data Types**: Exhaustive pattern matching for all cases
- **Module Signatures**: Private constructor pattern for validated types
- **Option Types**: No null pointer exceptions possible
- **Result Types**: Explicit error handling with typed errors

### Validated Types (Smart Constructors)
```ocaml
module ValidatedPath : sig
  type t  (* Abstract - cannot construct directly *)
  val create : string -> (t, string) result
  val to_string : t -> string
  val exists : t -> bool
end
```

### Pure Functional Core
- `calculate_entropy` - Pure function, no side effects
- `detect_file_type` - Pattern matching on magic bytes
- `match_signatures` - Immutable signature list
- `aggregate_family_votes` - Functional vote aggregation

### Immutable by Default
- All data structures are immutable
- Defensive copying for byte sequences
- No mutable state in core analysis logic

## Classification Capabilities

| Family | Detection Method |
|--------|-----------------|
| Ransomware | Encryption strings, ransom notes |
| Rootkit | LD_PRELOAD, sys_call_table hooks |
| Backdoor | Shell spawning, reverse connect |
| Cryptominer | Mining pool URLs, xmrig signatures |
| Spyware | Keylogger, screenshot functions |
| Trojan | Persistence mechanisms |
| Bot Client | C&C patterns, DDoS functions |

## Build

```bash
# Using dune
dune build
dune exec nullsec-classify -- /path/to/file

# Using ocamlfind
ocamlfind ocamlopt -package str,unix -linkpkg -o classify classify.ml
```

## Usage

```bash
# Analyze single file
./classify /usr/bin/suspicious

# Scan directory with max depth
./classify /var/tmp 3

# Results are color-coded:
# - RED: Critical threat
# - YELLOW: High threat  
# - CYAN: Medium threat
# - WHITE: Low threat
# - GREEN: Clean
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    NullSec Classify                         │
├─────────────────────────────────────────────────────────────┤
│  Validated Types (Smart Constructors)                       │
│  ├── ValidatedPath (path traversal protection)             │
│  └── ValidatedBytes (size bounds, defensive copy)          │
├─────────────────────────────────────────────────────────────┤
│  Pure Analysis Functions                                    │
│  ├── calculate_entropy : ValidatedBytes.t -> float         │
│  ├── detect_file_type : ValidatedBytes.t -> file_type      │
│  ├── match_signatures : ValidatedBytes.t -> matches        │
│  └── determine_threat_level : ... -> threat_level          │
├─────────────────────────────────────────────────────────────┤
│  Result Types for Error Handling                            │
│  └── (classification_result, analysis_error) result        │
└─────────────────────────────────────────────────────────────┘
```

## Type-Safe Error Handling

```ocaml
type analysis_error =
  | FileNotFound of string
  | ReadError of string
  | SizeError of string
  | ValidationError of string
  | InternalError of string

(* All errors are explicitly typed and must be handled *)
match analyze_file path with
| Ok result -> process_result result
| Error (FileNotFound path) -> handle_missing path
| Error (ReadError msg) -> handle_read_error msg
| Error (SizeError msg) -> handle_size_error msg
| Error (ValidationError msg) -> handle_validation msg
| Error (InternalError msg) -> handle_internal msg
```

## License

NullSec Proprietary - Part of the NullSec Security Framework


## 👤 Author

**bad-antics**
- GitHub: [@bad-antics](https://github.com/bad-antics)
- Website: [bad-antics.github.io](https://bad-antics.github.io)
- Discord: [discord.gg/killers](https://discord.gg/killers)

---

<div align="center">

**Part of the NullSec Security Framework**

</div>
