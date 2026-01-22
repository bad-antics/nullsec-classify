(*
 * NullSec Classify - Hardened Malware Classification Engine
 * Language: OCaml (Type-Safe Functional Programming)
 * Author: bad-antics
 * License: NullSec Proprietary
 * Security Level: Maximum Hardening
 *
 * Features:
 * - Strong static typing with algebraic data types
 * - Pattern matching for exhaustive case handling
 * - Immutable data structures by default
 * - Option types instead of null values
 * - Result types for explicit error handling
 * - Pure functions where possible
 * - Module system for encapsulation
 *)

open Printf

(* ============================================================================
 * Banner & Constants
 * ============================================================================ *)

let version = "1.0.0"

let banner = {|
 ██████╗██╗      █████╗ ███████╗███████╗██╗███████╗██╗   ██╗
██╔════╝██║     ██╔══██╗██╔════╝██╔════╝██║██╔════╝╚██╗ ██╔╝
██║     ██║     ███████║███████╗███████╗██║█████╗   ╚████╔╝ 
██║     ██║     ██╔══██║╚════██║╚════██║██║██╔══╝    ╚██╔╝  
╚██████╗███████╗██║  ██║███████║███████║██║██║        ██║   
 ╚═════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝╚═╝        ╚═╝   
                     bad-antics • v|} ^ version ^ {|
═══════════════════════════════════════════════════════════════
|}

(* Security constants - immutable by definition *)
let max_file_size = 100 * 1024 * 1024  (* 100MB *)
let max_path_length = 4096
let entropy_threshold = 7.5
let min_file_size = 16

(* ============================================================================
 * Custom Types & Validation
 * ============================================================================ *)

(* Validated path type - private constructor pattern *)
module ValidatedPath : sig
  type t
  val create : string -> (t, string) result
  val to_string : t -> string
  val exists : t -> bool
end = struct
  type t = { path : string; normalized : string }

  let is_safe_char c =
    let code = Char.code c in
    (code >= 48 && code <= 57) ||   (* 0-9 *)
    (code >= 65 && code <= 90) ||   (* A-Z *)
    (code >= 97 && code <= 122) ||  (* a-z *)
    c = '/' || c = '.' || c = '_' || c = '-'

  let contains_traversal path =
    let rec check i =
      if i >= String.length path - 1 then false
      else if path.[i] = '.' && path.[i + 1] = '.' then true
      else check (i + 1)
    in
    check 0

  let create raw_path =
    let len = String.length raw_path in
    if len = 0 then
      Error "Empty path"
    else if len > max_path_length then
      Error "Path too long"
    else if contains_traversal raw_path then
      Error "Path traversal detected"
    else if String.contains raw_path '\000' then
      Error "Null byte in path"
    else
      (* Check for injection characters *)
      let has_injection = 
        String.contains raw_path ';' ||
        String.contains raw_path '|' ||
        String.contains raw_path '`' ||
        String.contains raw_path '$'
      in
      if has_injection then
        Error "Injection character detected"
      else
        Ok { path = raw_path; normalized = raw_path }

  let to_string vp = vp.normalized
  
  let exists vp = Sys.file_exists vp.normalized
end

(* Validated byte sequence *)
module ValidatedBytes : sig
  type t
  val create : bytes -> (t, string) result
  val length : t -> int
  val get : t -> int -> int option
  val to_bytes : t -> bytes
  val sub : t -> int -> int -> t option
end = struct
  type t = { data : bytes; len : int }

  let create raw =
    let len = Bytes.length raw in
    if len > max_file_size then
      Error "Data exceeds maximum size"
    else
      Ok { data = Bytes.copy raw; len }  (* Defensive copy *)

  let length vb = vb.len

  let get vb idx =
    if idx >= 0 && idx < vb.len then
      Some (Char.code (Bytes.get vb.data idx))
    else
      None

  let to_bytes vb = Bytes.copy vb.data  (* Defensive copy *)

  let sub vb start len =
    if start >= 0 && len >= 0 && start + len <= vb.len then
      Some { data = Bytes.sub vb.data start len; len }
    else
      None
end

(* ============================================================================
 * Classification Types - Algebraic Data Types
 * ============================================================================ *)

(* Malware family classification *)
type malware_family =
  | Trojan
  | Ransomware
  | Spyware
  | Rootkit
  | Worm
  | Backdoor
  | Cryptominer
  | BotClient
  | Dropper
  | Unknown

(* File type detection *)
type file_type =
  | ELF
  | PE
  | MachO
  | Script
  | Archive
  | Document
  | UnknownType

(* Threat level *)
type threat_level =
  | Critical
  | High
  | Medium
  | Low
  | Clean

(* Classification result - complete information *)
type classification_result = {
  file_path : string;
  file_type : file_type;
  family : malware_family;
  threat : threat_level;
  confidence : float;
  entropy : float;
  signatures_matched : string list;
  suspicious_strings : string list;
  analysis_time_ms : float;
}

(* Analysis error types *)
type analysis_error =
  | FileNotFound of string
  | ReadError of string
  | SizeError of string
  | ValidationError of string
  | InternalError of string

(* ============================================================================
 * Pure Functions - Core Analysis Logic
 * ============================================================================ *)

(* Calculate Shannon entropy - pure function *)
let calculate_entropy (data : ValidatedBytes.t) : float =
  let len = ValidatedBytes.length data in
  if len = 0 then 0.0
  else
    (* Count byte frequencies *)
    let freq = Array.make 256 0 in
    for i = 0 to len - 1 do
      match ValidatedBytes.get data i with
      | Some b -> freq.(b) <- freq.(b) + 1
      | None -> ()
    done;
    
    (* Calculate entropy *)
    let total = float_of_int len in
    let entropy = ref 0.0 in
    Array.iter (fun count ->
      if count > 0 then
        let p = float_of_int count /. total in
        entropy := !entropy -. (p *. log p /. log 2.0)
    ) freq;
    !entropy

(* Detect file type from magic bytes - pure function *)
let detect_file_type (data : ValidatedBytes.t) : file_type =
  let len = ValidatedBytes.length data in
  if len < 4 then UnknownType
  else
    let get_byte i = ValidatedBytes.get data i in
    match (get_byte 0, get_byte 1, get_byte 2, get_byte 3) with
    | (Some 0x7f, Some 0x45, Some 0x4c, Some 0x46) -> ELF      (* \x7fELF *)
    | (Some 0x4d, Some 0x5a, _, _) -> PE                        (* MZ *)
    | (Some 0xcf, Some 0xfa, Some 0xed, Some 0xfe) -> MachO    (* Mach-O 64 *)
    | (Some 0xce, Some 0xfa, Some 0xed, Some 0xfe) -> MachO    (* Mach-O 32 *)
    | (Some 0xfe, Some 0xed, Some 0xfa, Some 0xcf) -> MachO    (* Mach-O 64 BE *)
    | (Some 0xfe, Some 0xed, Some 0xfa, Some 0xce) -> MachO    (* Mach-O 32 BE *)
    | (Some 0x50, Some 0x4b, Some 0x03, Some 0x04) -> Archive  (* ZIP *)
    | (Some 0x1f, Some 0x8b, _, _) -> Archive                   (* GZIP *)
    | (Some 0x23, Some 0x21, _, _) -> Script                    (* #! *)
    | _ -> UnknownType

(* Known malware signatures - immutable list *)
let malware_signatures = [
  (* Rootkit signatures *)
  ("LD_PRELOAD", Rootkit, 0.8);
  ("sys_call_table", Rootkit, 0.9);
  ("hide_pid", Rootkit, 0.85);
  ("getdents64", Rootkit, 0.7);
  
  (* Backdoor signatures *)
  ("/bin/sh", Backdoor, 0.5);
  ("reverse_shell", Backdoor, 0.9);
  ("bind_shell", Backdoor, 0.9);
  ("connect_back", Backdoor, 0.85);
  
  (* Cryptominer signatures *)
  ("xmrig", Cryptominer, 0.95);
  ("stratum+tcp", Cryptominer, 0.9);
  ("pool.mining", Cryptominer, 0.85);
  ("monero", Cryptominer, 0.8);
  
  (* Ransomware signatures *)
  ("YOUR FILES HAVE BEEN ENCRYPTED", Ransomware, 0.95);
  ("bitcoin", Ransomware, 0.4);
  (".encrypted", Ransomware, 0.6);
  ("AES-256", Ransomware, 0.3);
  
  (* Spyware signatures *)
  ("keylog", Spyware, 0.85);
  ("screenshot", Spyware, 0.6);
  ("clipboard", Spyware, 0.5);
  ("webcam", Spyware, 0.7);
  
  (* Trojan signatures *)
  ("RAT", Trojan, 0.7);
  ("persistence", Trojan, 0.5);
  ("autorun", Trojan, 0.6);
  ("startup", Trojan, 0.4);
  
  (* Bot signatures *)
  ("botnet", BotClient, 0.9);
  ("ddos", BotClient, 0.85);
  ("flood", BotClient, 0.7);
  ("irc.connect", BotClient, 0.8);
]

(* Suspicious string patterns *)
let suspicious_patterns = [
  "/etc/passwd";
  "/etc/shadow";
  "/dev/null";
  "ptrace";
  "mmap";
  "execve";
  "socket";
  "connect";
  "fork";
  "prctl";
  "setuid";
  "setgid";
  "chmod 777";
  "rm -rf";
  "wget";
  "curl";
  "nc -e";
  "bash -i";
  "python -c";
]

(* Search for string in bytes - case insensitive *)
let bytes_contains_string (data : ValidatedBytes.t) (pattern : string) : bool =
  let data_bytes = ValidatedBytes.to_bytes data in
  let data_str = Bytes.to_string data_bytes |> String.lowercase_ascii in
  let pattern_lower = String.lowercase_ascii pattern in
  try
    let _ = Str.search_forward (Str.regexp_string pattern_lower) data_str 0 in
    true
  with Not_found -> false

(* Match signatures against data - pure function returning matches *)
let match_signatures (data : ValidatedBytes.t) : (string * malware_family * float) list =
  List.filter (fun (sig_str, _, _) ->
    bytes_contains_string data sig_str
  ) malware_signatures

(* Find suspicious strings in data *)
let find_suspicious_strings (data : ValidatedBytes.t) : string list =
  List.filter (fun pattern ->
    bytes_contains_string data pattern
  ) suspicious_patterns

(* Aggregate family votes with confidence weighting *)
let aggregate_family_votes (matches : (string * malware_family * float) list) 
    : (malware_family * float) =
  if List.length matches = 0 then
    (Unknown, 0.0)
  else
    (* Group by family and sum confidence *)
    let family_scores = Hashtbl.create 16 in
    List.iter (fun (_, family, conf) ->
      let current = 
        try Hashtbl.find family_scores family 
        with Not_found -> 0.0 
      in
      Hashtbl.replace family_scores family (current +. conf)
    ) matches;
    
    (* Find highest scoring family *)
    let best_family = ref Unknown in
    let best_score = ref 0.0 in
    Hashtbl.iter (fun family score ->
      if score > !best_score then begin
        best_family := family;
        best_score := score
      end
    ) family_scores;
    
    (* Normalize confidence to 0-1 range *)
    let normalized_conf = min 1.0 (!best_score /. 5.0) in
    (!best_family, normalized_conf)

(* Determine threat level - pure function *)
let determine_threat_level (entropy : float) (family : malware_family) 
    (confidence : float) (susp_count : int) : threat_level =
  let base_score = 
    match family with
    | Ransomware -> 90
    | Rootkit -> 85
    | Backdoor -> 80
    | BotClient -> 75
    | Cryptominer -> 70
    | Spyware -> 65
    | Trojan -> 60
    | Worm -> 55
    | Dropper -> 50
    | Unknown -> 0
  in
  
  let entropy_bonus = if entropy > entropy_threshold then 15 else 0 in
  let susp_bonus = min 20 (susp_count * 2) in
  let conf_multiplier = confidence in
  
  let final_score = 
    int_of_float (float_of_int (base_score + entropy_bonus + susp_bonus) *. conf_multiplier)
  in
  
  if final_score >= 80 then Critical
  else if final_score >= 60 then High
  else if final_score >= 40 then Medium
  else if final_score >= 20 then Low
  else Clean

(* ============================================================================
 * File I/O with Proper Error Handling
 * ============================================================================ *)

(* Safe file reading with Result type *)
let read_file_safe (path : ValidatedPath.t) : (ValidatedBytes.t, analysis_error) result =
  let path_str = ValidatedPath.to_string path in
  if not (ValidatedPath.exists path) then
    Error (FileNotFound path_str)
  else
    try
      let ic = open_in_bin path_str in
      let size = in_channel_length ic in
      if size > max_file_size then begin
        close_in ic;
        Error (SizeError (sprintf "File too large: %d bytes" size))
      end
      else if size < min_file_size then begin
        close_in ic;
        Error (SizeError (sprintf "File too small: %d bytes" size))
      end
      else begin
        let buffer = Bytes.create size in
        really_input ic buffer 0 size;
        close_in ic;
        match ValidatedBytes.create buffer with
        | Ok vb -> Ok vb
        | Error msg -> Error (ValidationError msg)
      end
    with
    | Sys_error msg -> Error (ReadError msg)
    | End_of_file -> Error (ReadError "Unexpected end of file")

(* ============================================================================
 * Main Analysis Pipeline
 * ============================================================================ *)

(* Analyze a single file - returns Result *)
let analyze_file (path : ValidatedPath.t) : (classification_result, analysis_error) result =
  let start_time = Unix.gettimeofday () in
  let path_str = ValidatedPath.to_string path in
  
  match read_file_safe path with
  | Error e -> Error e
  | Ok data ->
    (* Calculate features *)
    let entropy = calculate_entropy data in
    let file_type = detect_file_type data in
    let sig_matches = match_signatures data in
    let susp_strings = find_suspicious_strings data in
    
    (* Aggregate results *)
    let (family, confidence) = aggregate_family_votes sig_matches in
    let threat = determine_threat_level entropy family confidence (List.length susp_strings) in
    
    let end_time = Unix.gettimeofday () in
    let elapsed_ms = (end_time -. start_time) *. 1000.0 in
    
    Ok {
      file_path = path_str;
      file_type;
      family;
      threat;
      confidence;
      entropy;
      signatures_matched = List.map (fun (s, _, _) -> s) sig_matches;
      suspicious_strings = susp_strings;
      analysis_time_ms = elapsed_ms;
    }

(* ============================================================================
 * Pretty Printing
 * ============================================================================ *)

let string_of_file_type = function
  | ELF -> "ELF"
  | PE -> "PE"
  | MachO -> "Mach-O"
  | Script -> "Script"
  | Archive -> "Archive"
  | Document -> "Document"
  | UnknownType -> "Unknown"

let string_of_family = function
  | Trojan -> "Trojan"
  | Ransomware -> "Ransomware"
  | Spyware -> "Spyware"
  | Rootkit -> "Rootkit"
  | Worm -> "Worm"
  | Backdoor -> "Backdoor"
  | Cryptominer -> "Cryptominer"
  | BotClient -> "Bot Client"
  | Dropper -> "Dropper"
  | Unknown -> "Unknown/Benign"

let string_of_threat = function
  | Critical -> "\027[31mCRITICAL\027[0m"
  | High -> "\027[33mHIGH\027[0m"
  | Medium -> "\027[36mMEDIUM\027[0m"
  | Low -> "\027[37mLOW\027[0m"
  | Clean -> "\027[32mCLEAN\027[0m"

let print_result (result : classification_result) : unit =
  printf "\n═══════════════════════════════════════════════════════════════\n";
  printf "  File: %s\n" result.file_path;
  printf "═══════════════════════════════════════════════════════════════\n";
  printf "  Type:       %s\n" (string_of_file_type result.file_type);
  printf "  Family:     %s\n" (string_of_family result.family);
  printf "  Threat:     %s\n" (string_of_threat result.threat);
  printf "  Confidence: %.1f%%\n" (result.confidence *. 100.0);
  printf "  Entropy:    %.2f bits/byte\n" result.entropy;
  printf "  Time:       %.2f ms\n" result.analysis_time_ms;
  
  if List.length result.signatures_matched > 0 then begin
    printf "\n  Signatures Matched:\n";
    List.iter (fun s -> printf "    • %s\n" s) result.signatures_matched
  end;
  
  if List.length result.suspicious_strings > 0 then begin
    printf "\n  Suspicious Strings (%d found):\n" (List.length result.suspicious_strings);
    List.iteri (fun i s ->
      if i < 10 then printf "    • %s\n" s
      else if i = 10 then printf "    • ... and %d more\n" (List.length result.suspicious_strings - 10)
    ) result.suspicious_strings
  end;
  
  printf "═══════════════════════════════════════════════════════════════\n"

let print_error (err : analysis_error) : unit =
  let msg = match err with
    | FileNotFound path -> sprintf "File not found: %s" path
    | ReadError msg -> sprintf "Read error: %s" msg
    | SizeError msg -> sprintf "Size error: %s" msg
    | ValidationError msg -> sprintf "Validation error: %s" msg
    | InternalError msg -> sprintf "Internal error: %s" msg
  in
  printf "\027[31m[ERROR]\027[0m %s\n" msg

(* ============================================================================
 * Directory Scanning with Bounded Recursion
 * ============================================================================ *)

let scan_directory (dir_path : ValidatedPath.t) (max_depth : int) 
    : (classification_result list, analysis_error) result =
  let results = ref [] in
  let errors = ref 0 in
  
  let rec scan path depth =
    if depth > max_depth then ()
    else
      let path_str = ValidatedPath.to_string path in
      if Sys.is_directory path_str then begin
        try
          let entries = Sys.readdir path_str in
          Array.iter (fun entry ->
            let full_path = Filename.concat path_str entry in
            match ValidatedPath.create full_path with
            | Ok vp -> scan vp (depth + 1)
            | Error _ -> incr errors
          ) entries
        with Sys_error _ -> incr errors
      end
      else begin
        match analyze_file path with
        | Ok result -> 
          if result.threat <> Clean then
            results := result :: !results
        | Error _ -> incr errors
      end
  in
  
  scan dir_path 0;
  Ok (List.rev !results)

(* ============================================================================
 * Entry Point
 * ============================================================================ *)

let () =
  print_string banner;
  
  if Array.length Sys.argv < 2 then begin
    printf "\nUsage: %s <file_or_directory> [max_depth]\n" Sys.argv.(0);
    printf "\nExamples:\n";
    printf "  %s /usr/bin/suspicious_binary\n" Sys.argv.(0);
    printf "  %s /var/tmp 3\n" Sys.argv.(0);
    exit 1
  end;
  
  let target = Sys.argv.(1) in
  let max_depth = 
    if Array.length Sys.argv >= 3 then
      try int_of_string Sys.argv.(2)
      with Failure _ -> 5
    else 5
  in
  
  printf "[\027[36m*\027[0m] Analyzing: %s\n" target;
  
  match ValidatedPath.create target with
  | Error msg ->
    printf "\027[31m[ERROR]\027[0m Invalid path: %s\n" msg;
    exit 1
  | Ok vpath ->
    if not (ValidatedPath.exists vpath) then begin
      printf "\027[31m[ERROR]\027[0m Path does not exist: %s\n" target;
      exit 1
    end;
    
    let target_str = ValidatedPath.to_string vpath in
    if Sys.is_directory target_str then begin
      printf "[\027[36m*\027[0m] Scanning directory (max depth: %d)...\n" max_depth;
      match scan_directory vpath max_depth with
      | Ok results ->
        if List.length results = 0 then
          printf "\n\027[32m[✓]\027[0m No threats detected\n"
        else begin
          printf "\n\027[33m[!]\027[0m Found %d potential threats:\n" (List.length results);
          List.iter print_result results
        end
      | Error e -> print_error e
    end
    else begin
      match analyze_file vpath with
      | Ok result -> print_result result
      | Error e -> print_error e
    end;
    
    printf "\n[\027[32m+\027[0m] Analysis complete.\n"
